from __future__ import annotations

import hmac
import json
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pydantic import BaseModel, ConfigDict, Field

from .alfagen import AlfaGenProvider
from .core import (
    BaselineDetector,
    Gateway,
    MemoryVault,
    Policy,
    ProcessingError,
    SQLiteVault,
    VaultError,
)
from .detection_cache import CachedDetector
from .field_rules import FieldRule
from .observability import AuditMiddleware, configure_logging, emit
from .policy_preview import preview_policy
from .process import PayloadConflict, ProcessService
from .providers import LLMProvider, LocalEcho
from .sandbox import compare_policies
from .workers import WorkerBusy, WorkerPool


class TextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=1_000_000)


class RestoreRequest(TextRequest):
    text: str = Field(min_length=1, max_length=16_000_000)
    session_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class ComparisonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detect_types: set[str] = Field(max_length=64)


class PolicyPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=16_384)
    candidate: Policy


class ProcessRequest(BaseModel):
    """Контракт автопроверки: payload + payload_id."""
    model_config = ConfigDict(extra="forbid")
    payload: str = Field(min_length=1, max_length=16_000_000)
    payload_id: str = Field(min_length=1, max_length=128)


def _validate_app_options(process_completed_ttl, process_capacity, process_max_bytes, process_workers):
    if not 1 <= process_completed_ttl <= 3600:
        raise ValueError("invalid_completed_ttl")
    if process_capacity < 0 or process_max_bytes < 0:
        raise ValueError("invalid_process_capacity")
    if not 1 <= process_workers <= 32:
        raise ValueError("invalid_worker_capacity")


def _validate_provider(provider, allow_alfagen):
    if not provider.local_only and not (allow_alfagen and isinstance(provider, AlfaGenProvider)):
        raise ValueError("External LLM providers are disabled until detector coverage is validated")


def _validate_credentials(credentials, policies):
    if not credentials or any(len(v) < 32 for v in credentials.values()):
        raise ValueError("Configure API keys of at least 32 characters")
    if set(credentials) - set(policies):
        raise ValueError("Every credential must reference a configured system")


def _build_metrics(registry, detector, process_pool, large_pool, process_service):
    for key in ("hits", "misses", "bypasses", "entries"):
        Gauge(f"privacy_detection_cache_{key}", "Detection cache statistics", registry=registry).set_function(
            lambda key=key: detector.stats()[key])
    requests = Counter("privacy_requests_total", "Processed operations",
                       ["operation", "status"], registry=registry)
    latency = Histogram("privacy_operation_seconds", "Processing time; roundtrip includes provider",
                        ["operation"], registry=registry)
    entities = Counter("privacy_entities_total", "Detected entity count",
                       ["kind"], registry=registry)
    http_requests = Counter("privacy_http_requests_total", "All HTTP outcomes",
                            ["operation", "status_code"], registry=registry)
    http_latency = Histogram("privacy_http_seconds", "HTTP time including validation and provider",
                             ["operation"], registry=registry)
    Gauge("privacy_process_inflight", "Admitted short process requests", registry=registry).set_function(
        process_pool.inflight)
    Gauge("privacy_process_large_inflight", "Admitted large requests", registry=registry).set_function(
        large_pool.inflight)
    Gauge("privacy_process_live_pairs", "Retained evaluator pairs", registry=registry).set_function(
        process_service.vault.count)
    Gauge("privacy_process_encrypted_bytes", "Encrypted evaluator bytes", registry=registry).set_function(
        lambda: process_service.vault.used_bytes)
    return requests, latency, entities, http_requests, http_latency


def _build_process_service(gateway, detector, policies, process_store, process_capacity,
                           process_max_bytes, process_vault_key, process_vault_key_file,
                           process_completed_ttl):
    owner = "support-demo" if "support-demo" in policies else next(iter(policies))
    process_policy = Policy(version="evaluator-v1", detect_types=detector.supported_types,
                            session_ttl_seconds=policies[owner].session_ttl_seconds)
    if process_store is None:
        process_vault = MemoryVault(process_capacity, process_max_bytes)
    else:
        process_vault = SQLiteVault(process_store, process_capacity, process_max_bytes,
                                    key=process_vault_key, key_file=process_vault_key_file)
    return ProcessService(gateway, process_policy, process_vault, process_completed_ttl)


def _build_consumer(policies, credentials):
    def consumer(x_system_id: str | None = Header(default=None),
                 x_api_key: str | None = Header(default=None)) -> str:
        expected = credentials.get(x_system_id)
        if expected is None or x_api_key is None or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
            emit("authorization", status="denied")
            raise HTTPException(401, "unauthorized")
        if not policies[x_system_id].enabled:
            emit("authorization", status="disabled")
            raise HTTPException(403, "system_disabled")
        emit("authorization", status="ok", policy_version=policies[x_system_id].version)
        return x_system_id
    return consumer


def _build_run(requests, latency):
    def run(operation: str, action):
        started = time.perf_counter()
        status = "ok"
        try:
            return action()
        except PayloadConflict as exc:
            status = "error"
            raise HTTPException(409, str(exc)) from None
        except VaultError as exc:
            if operation == "process" and str(exc) in {"vault_unavailable", "process_busy"}:
                status = "overloaded"
                raise HTTPException(429, "capacity_exhausted", headers={"Retry-After": "1"}) from None
            status = "error"
            raise HTTPException(503 if str(exc) == "vault_unavailable" else 404, str(exc)) from None
        except ProcessingError as exc:
            status = "error"
            raise HTTPException(422, str(exc)) from None
        except HTTPException:
            status = "error"
            raise
        except (ValueError, TypeError, KeyError, IndexError, RuntimeError, OSError):
            status = "error"
            raise HTTPException(503, "processing_unavailable") from None
        finally:
            elapsed = time.perf_counter() - started
            requests.labels(operation, status).inc()
            latency.labels(operation).observe(elapsed)
            emit("operation_finished", operation=operation, status=status,
                 elapsed_ms=round(elapsed * 1000, 3))
    return run


def _build_mask(gateway, policies, entities):
    def mask(owner, text):
        result = gateway.mask(owner, text, policies[owner])
        for kind, count in result["detected_types"].items():
            entities.labels(kind).inc(count)
        emit("detection", types=result["detected_types"],
             policy_version=policies[owner].version)
        return result
    return mask


def _roundtrip_action(owner, text, mask, gateway, detector, policies, provider):
    result = mask(owner, text)
    pattern = r"\[\[PD:[^\[\]\r\n]+\]\]"
    if not provider.local_only and detector.detect(
        re.sub(pattern, " ", result["text"]), detector.supported_types
    ):
        raise ProcessingError("unsafe_provider_request")
    emit("stage_started", stage="provider")
    answer = provider.generate(result["text"])
    if not isinstance(answer, str) or len(answer) > 1_000_000:
        raise RuntimeError("provider_response_invalid")
    emit("stage_finished", stage="provider", status="ok")
    emit("stage_started", stage="output_guard")
    permitted = set(re.findall(pattern, result["text"]))
    returned = set(re.findall(pattern, answer))
    plain = re.sub(pattern, " ", answer)
    if returned - permitted or "[[PD:" in plain:
        raise ProcessingError("unknown_or_damaged_token")
    if detector.detect(plain, detector.supported_types):
        raise ProcessingError("unsafe_provider_response")
    emit("stage_finished", stage="output_guard", status="ok")
    restored = (gateway.restore(owner, result["session_id"], answer)
                if result["session_id"] else answer)
    return {"provider": provider.name, "masked": result, "raw_answer_from_llm": answer, "answer": restored}


def _register_v1_routes(app, consumer, run, mask, gateway, detector, policies, provider):
    @app.post("/v1/mask")
    def mask_endpoint(body: TextRequest, owner: str = Depends(consumer)):
        return run("mask", lambda: mask(owner, body.text))

    @app.post("/v1/policies/compare")
    def compare_endpoint(body: ComparisonRequest, owner: str = Depends(consumer)):
        if body.detect_types - detector.supported_types:
            raise HTTPException(422, "unsupported_types")

        def action():
            from .synthetic import generate
            rows = [row for row in generate() if row["split"] in {"test", "challenge"}]
            return compare_policies(rows, policies[owner].detect_types, body.detect_types, detector=detector)
        return run("policy_compare", action)

    @app.post("/v1/policies/preview")
    def preview_endpoint(body: PolicyPreviewRequest, owner: str = Depends(consumer)):
        return run("policy_preview", lambda: preview_policy(body.text, policies[owner], body.candidate, detector))

    @app.post("/v1/restore")
    def restore_endpoint(body: RestoreRequest, owner: str = Depends(consumer)):
        if not policies[owner].restore_enabled:
            raise HTTPException(403, "restore_disabled")
        return run("restore", lambda: {"text": gateway.restore(owner, body.session_id, body.text)})

    @app.post("/v1/proxy")
    @app.post("/v1/demo/roundtrip")
    def roundtrip(body: TextRequest, owner: str = Depends(consumer)):
        return run("roundtrip", lambda: _roundtrip_action(
            owner, body.text, mask, gateway, detector, policies, provider))


def _register_process_route(app, process_service, process_pool, large_pool, run, entities):
    @app.post("/process")
    async def process_endpoint(body: ProcessRequest):
        inline = process_service.can_inline(body.payload_id, body.payload)
        def action():
            result, counts = process_service.process(body.payload_id, body.payload, blocking=not inline)
            for kind, count in counts.items():
                entities.labels(kind).inc(count)
            return {"result": result}
        if inline:
            return await process_pool.run(run, "process", action, wait=True)
        try:
            return await large_pool.run(run, "process", action)
        except WorkerBusy:
            def busy():
                raise VaultError("process_busy")
            return run("process", busy)


def create_app(policies: dict[str, Policy], credentials: dict[str, str],
               provider: LLMProvider | None = None,
               allow_alfagen: bool = False,
               process_capacity: int = 100_000,
               process_max_bytes: int = 128 * 1024 * 1024,
               process_store: str | Path | None = None,
               process_vault_key: bytes | str | None = None,
               process_vault_key_file: str | Path | None = None,
               field_rules: list[FieldRule] | None = None,
               process_completed_ttl: int = 60,
               large_request_workers: int = 2,
               process_workers: int = 16) -> FastAPI:
    _validate_app_options(process_completed_ttl, process_capacity, process_max_bytes, process_workers)
    provider = provider or LocalEcho()
    _validate_provider(provider, allow_alfagen)
    _validate_credentials(credentials, policies)

    detector = CachedDetector(BaselineDetector(field_rules or ()))
    if any(p.detect_types - detector.supported_types for p in policies.values()):
        raise ValueError("Unsupported detector type in policy")

    gateway = Gateway(detector, MemoryVault())
    process_pool = WorkerPool(process_workers, thread_name_prefix="privacy-process")
    large_pool = WorkerPool(large_request_workers)
    process_service = _build_process_service(
        gateway, detector, policies, process_store, process_capacity, process_max_bytes,
        process_vault_key, process_vault_key_file, process_completed_ttl)

    registry = CollectorRegistry()
    requests, latency, entities, http_requests, http_latency = _build_metrics(
        registry, detector, process_pool, large_pool, process_service)

    @asynccontextmanager
    async def lifespan(_):
        try:
            yield
        finally:
            process_pool.close()
            large_pool.close()
            if hasattr(process_service.vault, "close"):
                process_service.vault.close()

    app = FastAPI(title="Alpha Privacy Gateway — scaffold", version="0.1.0", lifespan=lifespan)
    buffer_gauge = Gauge("privacy_request_buffer_bytes", "Reserved incoming body bytes; not total RSS", registry=registry)
    app.add_middleware(AuditMiddleware, counter=http_requests, histogram=http_latency, buffer_gauge=buffer_gauge)

    consumer = _build_consumer(policies, credentials)
    run = _build_run(requests, latency)
    mask = _build_mask(gateway, policies, entities)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_, exc):
        emit("validation", status="denied")
        return JSONResponse(status_code=422, content={"detail": "invalid_request"})

    @app.get("/health/live")
    async def health():
        return {"status": "ok", "mode": provider.name,
                "external_llm_enabled": not provider.local_only,
                "supported_types": sorted(detector.supported_types)}

    @app.get("/metrics")
    def metrics(owner: str = Depends(consumer)):
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    _register_v1_routes(app, consumer, run, mask, gateway, detector, policies, provider)
    _register_process_route(app, process_service, process_pool, large_pool, run, entities)
    return app


def from_env() -> FastAPI:
    path = Path(os.environ.get("POLICY_FILE", "config/policies.json"))
    policies = {
        name: Policy.model_validate(value)
        for name, value in json.loads(path.read_text(encoding="utf-8")).items()
    }
    credentials = json.loads(os.environ.get("GATEWAY_API_KEYS", "{}"))
    storage_options = {
        "process_capacity": int(os.environ.get("PROCESS_CAPACITY", "100000")),
        "process_max_bytes": int(os.environ.get("PROCESS_MAX_BYTES", str(128 * 1024 * 1024))),
        "process_completed_ttl": int(os.environ.get("PROCESS_COMPLETED_TTL", "60")),
        "large_request_workers": int(os.environ.get("PROCESS_LARGE_WORKERS", "2")),
        "process_workers": int(os.environ.get("PROCESS_WORKERS", "16")),
    }
    if any(value < 0 for value in storage_options.values()):
        raise ValueError("invalid_process_capacity")
    if not 1 <= storage_options["process_completed_ttl"] <= 3600:
        raise ValueError("invalid_completed_ttl")
    if rules_file := os.environ.get("RULES_FILE"):
        storage_options["field_rules"] = [FieldRule.model_validate(rule) for rule in
                                         json.loads(Path(rules_file).read_text(encoding="utf-8"))]
    # Keep the fastest single-process default for the judge's local demo. Set
    # PROCESS_VAULT_DB (and a shared key file or PROCESS_VAULT_KEY) when using
    # multiple uvicorn workers; then all workers share the same encrypted WAL.
    if process_db := os.environ.get("PROCESS_VAULT_DB"):
        storage_options.update(
            process_store=process_db,
            process_vault_key=os.environ.get("PROCESS_VAULT_KEY"),
            process_vault_key_file=os.environ.get("PROCESS_VAULT_KEY_FILE", ".runtime/process-vault.key"),
        )
    configure_logging(os.environ.get("AUDIT_LOG_DIR"))
    selection = os.environ.get("LLM_PROVIDER", "local-echo")
    if selection == "alfagen":
        api_key = os.environ.get("ALFAGEN_API_KEY")
        key_file = os.environ.get("ALFAGEN_KEY_FILE")
        if not api_key and not key_file:
            raise ValueError("ALFAGEN_API_KEY or ALFAGEN_KEY_FILE is required")
        provider = AlfaGenProvider(
            key_file=key_file,
            ca_file=os.environ.get("ALFAGEN_CA_FILE"),
            base_url=os.environ.get("ALFAGEN_BASE_URL", "https://alfagen.alfabank.ru/continue-dev/"),
            api_key=api_key,
        )
        return create_app(policies, credentials, provider, allow_alfagen=True, **storage_options)
    if selection != "local-echo":
        raise ValueError("unsupported_provider")
    return create_app(policies, credentials, **storage_options)
