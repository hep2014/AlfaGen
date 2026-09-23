"""Reproducible local HTTP load, closed-loop pairs with a concurrency ramp.

Run: python -m alpha_privacy.benchmark --output reports/performance.json
Use --url to measure an already running instance with its actual logging setup.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

from .load_client import RawConnection

TLS_CONTEXT = ssl.create_default_context()
MAX_RETRY_DELAY = 1.0
REQUEST_TIMEOUT_SECONDS = 10.0


def summary(samples):
    samples = sorted(samples)
    if not samples:
        return {}
    return {"mean_ms": sum(samples) / len(samples), **{
        f"p{p}_ms": samples[max(0, math.ceil(len(samples) * p / 100) - 1)]
        for p in (50, 95, 99)
    }}


def retry_delay(value):
    """Honor Retry-After with a bounded wait, including HTTP-date values."""
    try:
        delay = float(value)
    except (TypeError, ValueError):
        try:
            delay = parsedate_to_datetime(value).timestamp() - time.time()
        except (TypeError, ValueError, OverflowError, AttributeError):
            return MAX_RETRY_DELAY
    return min(MAX_RETRY_DELAY, max(0.0, delay)) if math.isfinite(delay) else MAX_RETRY_DELAY


@dataclass(frozen=True)
class StepResult:
    response: httpx.Response | None
    retry_attempts: int
    exhausted: bool
    elapsed_ms: float = 0.0


async def request_step(connection, payload, deadline, retries, record):
    """Retry a single immutable protocol step; never replace its pair identifier."""
    attempts = 0
    while time.perf_counter() < deadline:
        begin = time.perf_counter()
        response = None
        try:
            # The phase deadline controls admission of a new step. Once the
            # request is on the wire, let the client's normal timeout finish
            # it; otherwise every phase manufactures a transport failure at
            # its boundary.
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                response = await connection.post("/process", json=payload)
        except (httpx.HTTPError, TimeoutError):
            pass
        attempts += 1
        elapsed = (time.perf_counter() - begin) * 1000
        record(response, elapsed)
        if response is not None and response.status_code != 429:
            return StepResult(response, attempts - 1, False, elapsed)
        if attempts > retries:
            break
        delay = retry_delay(response.headers.get("Retry-After")) if response is not None else MAX_RETRY_DELAY
        # Do not start a sleep that would consume the entire remaining phase.
        if time.perf_counter() + delay >= deadline:
            break
        await asyncio.sleep(delay)
    return StepResult(None, max(0, attempts - 1), True)


def dense_text():
    # Different values force 22,000 distinct masks and exercise expansion on restore.
    return "; ".join(f"synthetic-{index}@example.org" for index in range(22_000))


async def _process_step(connection, identifier, original, deadline, retries, record, state, rows, index, sequence):
    payload = original
    for operation in ("mask", "restore"):
        result = await request_step(connection, {"payload_id": identifier, "payload": payload},
                                    deadline, retries, record)
        state["retry_attempts"] += result.retry_attempts
        if result.exhausted:
            state["exhausted_pairs"] += 1
            return False
        response = result.response
        if response.status_code != 200:
            return False
        state["operations"][operation].append(result.elapsed_ms)
        try:
            value = response.json()
            payload = value.get("result") if isinstance(value, dict) else None
        except ValueError:
            payload = None
        if operation == "mask":
            plain = re.sub(r"\[\[PD:[^\[\]\r\n]+\]\]", "", payload) if isinstance(payload, str) else ""
            row = rows[(index + sequence) % len(rows)] if rows else None
            wrong = (not isinstance(payload, str) or
                     (any(e["value"] in plain for e in row["entities"]) if row else
                      "@example.org" in plain or "Иванов" in plain))
            if row and not row["entities"] and payload != original:
                wrong = True
            if wrong:
                state["incorrect"] += 1
                return False
        if operation == "restore":
            state["roundtrips"] += 1
            state["incorrect"] += payload != original
    return True


async def _connected_worker(index, connection, run_id, deadline, rows, dense, large_prefix,
                            corpus, retries, record, state):
    sequence = 0
    while time.perf_counter() < deadline:
        identifier = f"{run_id}-{index}-{sequence}"
        original = f"Клиент Иванов Иван; email synthetic-{index}-{sequence}@example.org; телефон +7 (999) 123-45-67."
        if corpus == "repeated":
            original = f"Клиент Иванов Иван; email synthetic-{(index + sequence) % 32}@example.org; телефон +7 (999) 123-45-67."
        elif rows:
            original = rows[(index + sequence) % len(rows)]["text"]
        elif dense is not None:
            original = dense
        elif large_prefix:
            original = large_prefix + original
        if not await _process_step(connection, identifier, original, deadline, retries, record,
                                   state, rows, index, sequence):
            break
        sequence += 1


async def phase(client, concurrency, seconds, transport="httpx", corpus="unique", retries=2):
    statuses, latencies, successful = Counter(), [], []
    operations = {"mask": [], "restore": []}
    transport_errors = 0
    state = {"roundtrips": 0, "incorrect": 0, "retry_attempts": 0, "exhausted_pairs": 0,
             "operations": operations}
    run_id = uuid.uuid4().hex
    from .robustness import generate_robustness
    rows = generate_robustness() if corpus == "mixed" else []
    dense = dense_text() if corpus == "large-dense" else None
    large_prefix = "слово " * 100_000 if corpus == "large" else ""
    started = time.perf_counter()
    deadline = started + seconds

    def record(response, elapsed):
        nonlocal transport_errors
        latencies.append(elapsed)
        if response is None:
            transport_errors += 1
        else:
            statuses[str(response.status_code)] += 1
            if response.status_code == 200:
                successful.append(elapsed)

    async def worker(index):
        connection = (RawConnection(client.base_url, TLS_CONTEXT) if transport == "raw" else
                      httpx.AsyncClient(base_url=client.base_url, trust_env=False, verify=TLS_CONTEXT, timeout=10,
                                        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1)))
        async with connection:
            await _connected_worker(index, connection, run_id, deadline, rows, dense, large_prefix,
                                    corpus, retries, record, state)

    await asyncio.gather(*(worker(i) for i in range(concurrency)))
    elapsed = time.perf_counter() - started
    return {"concurrency": concurrency, "elapsed_seconds": elapsed,
            "requests": len(latencies), "rps": len(latencies) / elapsed,
            "successful_rps": len(successful) / elapsed, "statuses": dict(statuses),
            "transport_errors": transport_errors, "completed_pairs": state["roundtrips"],
            "retries": retries, "retry_attempts": state["retry_attempts"], "exhausted_pairs": state["exhausted_pairs"],
            "incorrect_results": state["incorrect"], "all_requests": summary(latencies),
            "successful_requests": summary(successful),
            "operations": {op: summary(values) for op, values in operations.items()}}


async def measure(url, seconds, transport="httpx", corpus="unique", connections=(20, 100, 200), metric_headers=None, retries=2):
    async with httpx.AsyncClient(base_url=url, trust_env=False, verify=TLS_CONTEXT, timeout=30,
                                limits=httpx.Limits(max_connections=200, max_keepalive_connections=200)) as client:
        for _ in range(100):
            try:
                response = await client.get("/health/live")
                if response.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("benchmark_server_unavailable")
        phases = []
        for concurrency in connections:
            result = await phase(client, concurrency, seconds, transport, corpus, retries)
            phases.append(result)
            print(json.dumps(result), flush=True)
        metrics = {}
        if metric_headers:
            response = await client.get("/metrics", headers=metric_headers)
            response.raise_for_status()
            for line in response.text.splitlines():
                if line.startswith(("privacy_process_", "privacy_detection_cache_", "privacy_request_buffer_bytes")) or (
                    line.startswith(("privacy_operation_seconds_", "privacy_http_seconds_")) and 'operation="process"' in line
                ):
                    name, value = line.rsplit(" ", 1)
                    metrics[name] = float(value)
        return phases, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url")
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--output", default="reports/performance.json")
    parser.add_argument("--client", choices=("httpx", "raw"), default="httpx")
    parser.add_argument("--corpus", choices=("unique", "repeated", "mixed", "large", "large-dense"), default="unique")
    parser.add_argument("--connections", nargs="+", type=int, default=[20, 100, 200])
    parser.add_argument("--retries", type=int, default=2, help="Retries per HTTP step after 429 or transport errors")
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    if any(not 1 <= n <= 200 for n in args.connections):
        parser.error("--connections must be between 1 and 200")
    if not 0 <= args.retries <= 20:
        parser.error("--retries must be between 0 and 20")
    server = None
    url = args.url
    metric_headers = None
    try:
        if not url:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))  # NOSONAR: S1313 — loopback for the local benchmark server.
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}"  # NOSONAR: S1313 — loopback for the local benchmark server.
            key = uuid.uuid4().hex
            metric_headers = {"X-System-ID": "support-demo", "X-API-Key": key}
            env = dict(os.environ, GATEWAY_API_KEYS=json.dumps({"support-demo": key}),
                       LLM_PROVIDER="local-echo", AUDIT_LOG_DIR="")
            server = subprocess.Popen(  # NOSONAR: S603 — fixed interpreter and args, no untrusted input.
                [sys.executable, "-m", "uvicorn", "alpha_privacy.api:from_env", "--factory",
                 "--host", "127.0.0.1", "--port", str(port), "--no-access-log"], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        phases, metrics = asyncio.run(measure(url, args.seconds, args.client, args.corpus, args.connections, metric_headers, args.retries))
        report = {"platform": platform.platform(), "python": sys.version,
                  "cpu_count": os.cpu_count(), "client": args.client, "corpus": args.corpus,
                  "retries": args.retries, "max_retry_delay_seconds": MAX_RETRY_DELAY,
                  "source_sha256": hashlib.sha256(b"".join(p.name.encode() + p.read_bytes() for p in sorted(Path(__file__).parent.glob("*.py")))).hexdigest(),
                  "dependencies": {name: importlib.metadata.version(name) for name in ("fastapi", "uvicorn", "httpx", "cryptography")},
                  "mode": "closed-loop; sequential mask/restore per connection",
                  "server": "external" if args.url else "local, one uvicorn process; INFO audit to discarded stderr",
                  "limitations": "Synthetic texts; large adds 100,000 words (not tokenizer tokens); large-dense has 22,000 distinct emails; client and local server share a host; no LLM latency; not an open-loop 1000 RPS proof; phase deadline includes requests and retries",
                  "phases": phases, "server_metrics": metrics}
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
