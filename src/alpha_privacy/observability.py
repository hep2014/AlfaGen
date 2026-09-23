"""Structured audit events: deliberately no generic message/payload fields."""
from __future__ import annotations

import json
import logging
import secrets
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import ClassVar

request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
audit_enabled: ContextVar[bool] = ContextVar("audit_enabled", default=True)
logger = logging.getLogger("alpha_privacy.audit")
ALLOWED_FIELDS = {"stage", "status", "status_code", "elapsed_ms", "types", "policy_version", "operation"}


def emit(event: str, **fields) -> None:
    if not audit_enabled.get():
        return
    if fields.keys() - ALLOWED_FIELDS:
        raise ValueError("Unsupported audit field")
    if not logger.isEnabledFor(logging.INFO):
        return
    logger.info(json.dumps({"timestamp": datetime.now(UTC).isoformat(),
                            "event": event, "request_id": request_id.get(), **fields}, ensure_ascii=False))


@contextmanager
def quiet_audit():
    context = audit_enabled.set(False)
    try:
        yield
    finally:
        audit_enabled.reset(context)


def configure_logging(directory: str | None = None) -> None:
    logger.setLevel(logging.INFO)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)
    if directory:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(path / "audit.jsonl", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.propagate = False
    # Uvicorn access records contain attacker-controlled URLs, including query strings.
    logging.getLogger("uvicorn.access").disabled = True


class AuditMiddleware:
    """Bound request bytes before JSON parsing; track all HTTP outcomes without raw URLs."""

    ROUTES: ClassVar[dict[str, str]] = {"/process": "process", "/v1/mask": "mask", "/v1/restore": "restore", "/v1/proxy": "proxy",
              "/v1/policies/compare": "policy_compare",
              "/v1/policies/preview": "policy_preview",
              "/v1/demo/roundtrip": "roundtrip", "/metrics": "metrics",
              "/health/live": "health", "/docs": "docs", "/openapi.json": "schema"}

    def __init__(self, app, counter, histogram, max_body_bytes=32_000_000,
                 max_buffered_bytes=64_000_000, buffer_gauge=None):
        self.app, self.counter, self.histogram = app, counter, histogram
        self.max_body_bytes = max_body_bytes
        self.max_buffered_bytes = max_buffered_bytes
        self.buffered_bytes = 0
        self.buffer_lock = threading.Lock()
        self.buffer_gauge = buffer_gauge

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        context = request_id.set(secrets.token_hex(16))
        operation = self.ROUTES.get(scope["path"], "unknown")
        started = time.perf_counter()
        reserved_bytes = 0

        tracked_send, reject, state = self._make_send_wrappers(send)

        emit("request_started", operation=operation)
        try:
            body, reserved_bytes, _status = await self._read_body(receive, reject)
            if body is None:
                return

            consumed = False

            async def replay():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, tracked_send)
        except Exception:  # NOSONAR: S112 — middleware must convert any handler error to 503.
            emit("request_failed", operation=operation, status="internal_error")
            if not state["sent"]:
                await reject(503, "processing_unavailable")
            else:
                raise
        finally:
            with self.buffer_lock:
                self.buffered_bytes -= reserved_bytes
                if self.buffer_gauge is not None:
                    self.buffer_gauge.set(self.buffered_bytes)
            elapsed = time.perf_counter() - started
            self.counter.labels(operation, str(state["status"])).inc()
            self.histogram.labels(operation).observe(elapsed)
            emit("request_finished", operation=operation, status_code=state["status"], elapsed_ms=round(elapsed * 1000, 3))
            request_id.reset(context)

    def _make_send_wrappers(self, send):
        state = {"status": 500, "sent": False}

        async def tracked_send(message):
            if message["type"] == "http.response.start":
                state["status"], state["sent"] = message["status"], True
                message["headers"] = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"]
                message["headers"].append((b"x-request-id", request_id.get().encode()))
            await send(message)

        async def reject(code, detail):
            content = json.dumps({"detail": detail}).encode()
            headers = [(b"content-type", b"application/json"), (b"content-length", str(len(content)).encode())]
            if code == 429:
                headers.append((b"retry-after", b"1"))
            await tracked_send({"type": "http.response.start", "status": code,
                                "headers": headers})
            await tracked_send({"type": "http.response.body", "body": content})

        return tracked_send, reject, state

    async def _read_body(self, receive, reject):
        body = bytearray()
        reserved_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None, reserved_bytes, 499
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_body_bytes:
                await reject(413, "request_too_large")
                return None, reserved_bytes, 413
            with self.buffer_lock:
                accepted = self.buffered_bytes + len(chunk) <= self.max_buffered_bytes
                if accepted:
                    self.buffered_bytes += len(chunk)
                    reserved_bytes += len(chunk)
                    if self.buffer_gauge is not None:
                        self.buffer_gauge.set(self.buffered_bytes)
            if not accepted:
                await reject(429, "request_buffer_exhausted")
                return None, reserved_bytes, 429
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        return body, reserved_bytes, 200
