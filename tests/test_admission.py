import asyncio
import json
import threading
from contextvars import ContextVar

import httpx
import pytest
from prometheus_client import CollectorRegistry, Counter, Histogram

from alpha_privacy.api import create_app
from alpha_privacy.core import BaselineDetector, Policy
from alpha_privacy.observability import AuditMiddleware
from alpha_privacy.process import ProcessService
from alpha_privacy.workers import WorkerBusy, WorkerPool


def test_cancelled_caller_does_not_release_running_worker():
    entered, release = threading.Event(), threading.Event()
    marker = ContextVar("test_marker", default="missing")

    def work():
        entered.set()
        assert release.wait(5)
        assert marker.get() == "request-context"

    async def scenario():
        pool = WorkerPool(1)
        marker.set("request-context")
        task = asyncio.create_task(pool.run(work))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert pool.inflight() == 1
            with pytest.raises(WorkerBusy):
                await pool.run(lambda: None)
        finally:
            release.set()
            await asyncio.to_thread(pool.executor.shutdown, wait=True)
        assert pool.inflight() == 0

    asyncio.run(scenario())


def test_worker_exception_and_submission_failure_release_slots():
    async def scenario():
        pool = WorkerPool(1)
        def broken():
            raise RuntimeError("test_error")
        try:
            with pytest.raises(RuntimeError, match="test_error"):
                await pool.run(broken)
            assert pool.inflight() == 0
            assert await pool.run(lambda: 42) == 42
        finally:
            pool.close()
        with pytest.raises(RuntimeError):
            await pool.run(lambda: 42)
        assert pool.inflight() == 0
    asyncio.run(scenario())


def test_large_admission_is_bounded_and_retry_does_not_reserve_id(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = ProcessService.process
    def delayed(self, payload_id, payload, **kwargs):
        if payload_id == "large-one":
            entered.set()
            assert release.wait(5)
        return original(self, payload_id, payload, **kwargs)
    monkeypatch.setattr(ProcessService, "process", delayed)

    async def scenario():
        policy = Policy(version="1", detect_types=BaselineDetector.supported_types)
        app = create_app({"a": policy}, {"a": "a" * 32}, large_request_workers=1)
        headers = {"X-System-ID": "a", "X-API-Key": "a" * 32}
        body = {"payload_id": "large-two", "payload": "word " * 1000 + "b@example.org"}
        async with app.router.lifespan_context(app), httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                first = asyncio.create_task(client.post("/process", json={**body, "payload_id": "large-one"}))
                try:
                    assert await asyncio.to_thread(entered.wait, 2)
                    overloaded = await asyncio.wait_for(client.post("/process", json=body), 2)
                    assert overloaded.status_code == 429 and overloaded.headers["retry-after"] == "1"
                    assert (await client.get("/health/live")).status_code == 200
                    small = await client.post("/process", json={"payload_id": "small", "payload": "a@example.org"})
                    assert small.status_code == 200
                    metrics = (await client.get("/metrics", headers=headers)).text
                    assert "privacy_process_large_inflight 1.0" in metrics
                finally:
                    release.set()
                    assert (await first).status_code == 200
                retried = await client.post("/process", json=body)
                assert retried.status_code == 200
                restored = await client.post("/process", json={**body, "payload": retried.json()["result"]})
                assert restored.json() == {"result": body["payload"]}
                metrics = (await client.get("/metrics", headers=headers)).text
                assert "privacy_process_large_inflight 0.0" in metrics
    asyncio.run(scenario())


def test_aggregate_buffer_budget_released_on_cancellation_and_disconnect():
    async def scenario():
        started = asyncio.Event()
        async def app(scope, receive, send):
            await receive()
            if scope["path"] == "/hold":
                started.set()
                await asyncio.Event().wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        registry = CollectorRegistry()
        middleware = AuditMiddleware(app,
            Counter("test_http", "test", ["operation", "status"], registry=registry),
            Histogram("test_latency", "test", ["operation"], registry=registry),
            max_body_bytes=16, max_buffered_bytes=20)

        async def call(path, messages):
            output = []
            async def receive():
                return messages.pop(0)
            async def send(message):
                output.append(message)
            await middleware({"type": "http", "path": path}, receive, send)
            return output

        held = asyncio.create_task(call("/hold", [{"type": "http.request", "body": b"x" * 16}]))
        await started.wait()
        try:
            rejected = await call("/process", [{"type": "http.request", "body": b"y" * 8}])
            assert rejected[0]["status"] == 429
            assert dict(rejected[0]["headers"])[b"retry-after"] == b"1"
            assert json.loads(rejected[1]["body"]) == {"detail": "request_buffer_exhausted"}
            assert (await call("/health/live", [{"type": "http.request", "body": b""}]))[0]["status"] == 200
        finally:
            held.cancel()
            with pytest.raises(asyncio.CancelledError):
                await held
        assert middleware.buffered_bytes == 0
        await call("/process", [{"type": "http.request", "body": b"z" * 8, "more_body": True},
                                {"type": "http.disconnect"}])
        assert middleware.buffered_bytes == 0
        assert (await call("/process", [{"type": "http.request", "body": b"x" * 16}]))[0]["status"] == 200
    asyncio.run(scenario())


@pytest.mark.parametrize("kwargs", [{"large_request_workers": 0}, {"large_request_workers": 33},
                                   {"process_completed_ttl": 0}, {"process_completed_ttl": 3601},
                                   {"process_max_bytes": -1}, {"process_capacity": -1}])
def test_invalid_admission_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        create_app({"a": Policy(version="1", detect_types=set())}, {"a": "a" * 32}, **kwargs)
