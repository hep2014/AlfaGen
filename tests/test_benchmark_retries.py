"""The load tool must preserve pair identity and expose failed attempts."""
import asyncio
from datetime import UTC, datetime
from email.utils import format_datetime
from types import SimpleNamespace

import httpx
import pytest

from alpha_privacy import benchmark
from alpha_privacy.load_client import RawConnection


class Clock:
    def __init__(self):
        self.value = 0.0

    def perf_counter(self):
        return self.value

    def time(self):
        return 1_000.0

    async def sleep(self, seconds):
        self.value += seconds


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(benchmark, "time", clock)
    monkeypatch.setattr(benchmark.asyncio, "sleep", clock.sleep)
    return clock


class ScriptedConnection:
    def __init__(self, outcomes, clock=None):
        self.outcomes, self.clock, self.calls = list(outcomes), clock, []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def post(self, path, *, json):
        self.calls.append((path, dict(json)))
        outcome = self.outcomes.pop(0)
        if not self.outcomes and self.clock:
            self.clock.value = 100.0
        if isinstance(outcome, Exception):
            raise outcome
        if outcome == "mask":
            return httpx.Response(200, json={"result": "[[PD:EMAIL:opaque]]"})
        if outcome == "restore":
            return httpx.Response(200, json={"result": self.calls[0][1]["payload"]})
        return outcome


def busy(retry_after="0"):
    return httpx.Response(429, headers={"Retry-After": retry_after}, json={"detail": "busy"})


@pytest.mark.parametrize("outcomes,expected_retries,expected_429,expected_transport", [
    ([busy(), "mask", "restore"], 1, 1, 0),
    (["mask", busy(), "restore"], 1, 1, 0),
    ([busy(), "mask", busy(), "restore"], 2, 2, 0),
    ([httpx.TransportError("lost response"), "mask", "restore"], 1, 0, 1),
    (["mask", httpx.TransportError("lost response"), "restore"], 1, 0, 1),
])
def test_phase_retries_same_pair_and_counts_every_attempt(monkeypatch, clock, outcomes, expected_retries, expected_429, expected_transport):
    connection = ScriptedConnection(outcomes, clock)
    monkeypatch.setattr(benchmark.httpx, "AsyncClient", lambda **kwargs: connection)
    result = asyncio.run(benchmark.phase(SimpleNamespace(base_url="http://test"), 1, 100))

    calls = [payload for _, payload in connection.calls]
    assert len({payload["payload_id"] for payload in calls}) == 1
    original = calls[0]["payload"]
    assert {payload["payload"] for payload in calls} == {original, "[[PD:EMAIL:opaque]]"}
    first_restore = next(index for index, payload in enumerate(calls) if payload["payload"] != original)
    assert all(payload == calls[0] for payload in calls[:first_restore])
    assert all(payload == calls[first_restore] for payload in calls[first_restore:])
    assert result["requests"] == len(calls)
    assert result["statuses"].get("429", 0) == expected_429
    assert result["statuses"]["200"] == 2
    assert result["successful_rps"] == 2 / result["elapsed_seconds"]
    assert result["transport_errors"] == expected_transport
    assert result["retry_attempts"] == expected_retries
    assert result["completed_pairs"] == 1
    assert result["incorrect_results"] == result["exhausted_pairs"] == 0


@pytest.mark.parametrize("prefix", [[], ["mask"]])
def test_exhausted_step_does_not_discard_id_between_retries(monkeypatch, clock, prefix):
    connection = ScriptedConnection(prefix + [busy(), busy(), busy()], clock)
    monkeypatch.setattr(benchmark.httpx, "AsyncClient", lambda **kwargs: connection)
    result = asyncio.run(benchmark.phase(SimpleNamespace(base_url="http://test"), 1, 100))
    assert result["retry_attempts"] == 2
    assert result["exhausted_pairs"] == 1
    assert result["completed_pairs"] == 0
    assert result["statuses"]["429"] == 3
    assert connection.calls[-1] == connection.calls[-2] == connection.calls[-3]


@pytest.mark.parametrize("response", [httpx.Response(500), httpx.Response(200, content=b"not-json"),
                                     httpx.Response(200, json=[]), httpx.Response(200, json={"result": 7})])
def test_phase_exposes_errors_without_retrying_them(monkeypatch, clock, response):
    connection = ScriptedConnection([response], clock)
    monkeypatch.setattr(benchmark.httpx, "AsyncClient", lambda **kwargs: connection)
    result = asyncio.run(benchmark.phase(SimpleNamespace(base_url="http://test"), 1, 100))
    assert result["requests"] == 1
    assert result["retry_attempts"] == result["completed_pairs"] == 0
    assert result["statuses"] == {str(response.status_code): 1}
    assert result["incorrect_results"] == (response.status_code == 200)


@pytest.mark.parametrize("value,expected", [(None, 1), ("invalid", 1), ("nan", 1), ("inf", 1),
                                           ("120", 1), ("0.25", 0.25), ("-1", 0)])
def test_retry_after_is_bounded(value, expected):
    assert benchmark.retry_delay(value) == expected


def test_retry_after_http_date(clock):
    assert benchmark.retry_delay(format_datetime(datetime.fromtimestamp(1001, UTC))) == 1
    assert benchmark.retry_delay(format_datetime(datetime.fromtimestamp(999, UTC))) == 0


def test_retry_after_waits_within_shared_deadline(clock):
    connection = ScriptedConnection([busy("0.25"), httpx.Response(200)])
    attempts = []
    result = asyncio.run(benchmark.request_step(connection, {"payload_id": "id", "payload": "text"}, 0.5, 2,
                                               lambda response, elapsed: attempts.append(response.status_code)))
    assert clock.value == 0.25
    assert attempts == [429, 200]
    assert result.retry_attempts == 1
    assert not result.exhausted


def test_deadline_prevents_wait_and_retry(clock):
    connection = ScriptedConnection([busy("1")])
    attempts = []
    result = asyncio.run(benchmark.request_step(connection, {}, 0.5, 2,
                                               lambda response, elapsed: attempts.append(response.status_code)))
    assert result.exhausted
    assert result.retry_attempts == 0
    assert attempts == [429]
    assert clock.value == 0


def test_expired_deadline_sends_nothing(clock):
    connection = ScriptedConnection([])
    result = asyncio.run(benchmark.request_step(connection, {}, 0, 2, lambda *args: pytest.fail("unexpected attempt")))
    assert result.exhausted and result.retry_attempts == 0
    assert connection.calls == []


def test_zero_retries_sends_one_attempt(clock):
    connection = ScriptedConnection([busy("0")])
    result = asyncio.run(benchmark.request_step(connection, {}, 100, 0, lambda *args: None))
    assert result.exhausted and result.retry_attempts == 0
    assert len(connection.calls) == 1


def test_request_uses_client_timeout_after_admission(monkeypatch):
    monkeypatch.setattr(benchmark, "REQUEST_TIMEOUT_SECONDS", 0.01)
    class StalledConnection:
        async def post(self, *args, **kwargs):
            await asyncio.Event().wait()

    async def run():
        attempts = []
        result = await benchmark.request_step(StalledConnection(), {}, benchmark.time.perf_counter() + 1, 2,
                                              lambda response, elapsed: attempts.append(response))
        assert result.exhausted
        assert attempts == [None]

    asyncio.run(run())


def test_large_dense_corpus_contains_distinct_values_below_source_limit():
    text = benchmark.dense_text()
    emails = text.split("; ")
    assert len(text) < 1_000_000
    assert len(emails) == len(set(emails)) == 22_000
    assert all(email.startswith("synthetic-") and email.endswith("@example.org") for email in emails)


@pytest.mark.parametrize("broken", [b"HTTP/1.1 200 OK\r\n\r\n", b"HTTP/1.1\r\n\r\n",
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nxx"])
def test_raw_connection_reconnects_after_broken_response(broken):
    async def run():
        connections = 0

        async def handle(reader, writer):
            nonlocal connections
            connections += 1
            head = await reader.readuntil(b"\r\n\r\n")
            length = int(next(line.split(b":", 1)[1] for line in head.split(b"\r\n") if line.startswith(b"Content-Length:")))
            await reader.readexactly(length)
            response = broken if connections == 1 else b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"result\":\"ok\"}"
            writer.write(response)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            async with RawConnection(f"http://127.0.0.1:{port}", None) as connection:
                with pytest.raises(httpx.TransportError):
                    await connection.post("/process", json={"payload_id": "same", "payload": "text"})
                assert connection.writer is None
                response = await connection.post("/process", json={"payload_id": "same", "payload": "text"})
                assert response.json() == {"result": "ok"}
                assert connections == 2

    asyncio.run(run())
