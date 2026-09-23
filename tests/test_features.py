import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from alpha_privacy.api import create_app
from alpha_privacy.core import (
    BaselineDetector,
    CombinationRule,
    Gateway,
    MemoryVault,
    Policy,
    VaultError,
)
from alpha_privacy.detection_cache import CachedDetector
from alpha_privacy.field_rules import FieldRule
from alpha_privacy.process import ProcessService

ALL = BaselineDetector.supported_types


@pytest.mark.parametrize("owner", ["support-demo", "analytics-demo"])
def test_shipped_policies_protect_additional_documents(owner):
    data = json.loads((Path(__file__).parents[1] / "config" / "policies.json").read_text(encoding="utf-8"))
    policies = {name: Policy(**options) for name, options in data.items()}
    headers = {"X-System-ID": owner, "X-API-Key": "a" * 32}
    text = "Загранпаспорт: 72 1234567; свидетельство о рождении: IV-АБ 123456."
    with TestClient(create_app(policies, {owner: "a" * 32})) as client:
        response = client.post("/v1/mask", headers=headers, json={"text": text})
        assert response.status_code == 200
        masked = response.json()
        assert masked["detected_types"] == {"FOREIGN_PASSPORT": 1, "BIRTH_CERTIFICATE": 1}
        assert "72 1234567" not in masked["text"] and "IV-АБ 123456" not in masked["text"]
        if policies[owner].restore_enabled:
            restored = client.post("/v1/restore", headers=headers,
                                   json={"session_id": masked["session_id"], "text": masked["text"]})
            assert restored.status_code == 200
            assert restored.json()["text"] == text


def test_relation_preserving_tokens_are_scoped_to_session():
    gateway = Gateway(BaselineDetector(), MemoryVault())
    policy = Policy(version="1", detect_types=ALL)
    text = "a@example.org и a@example.org"
    first, second = [gateway.mask("a", text, policy) for _ in range(2)]
    assert first["text"].split(" и ")[0] == first["text"].split(" и ")[1]
    assert first["text"] != second["text"]
    assert gateway.restore("a", first["session_id"], first["text"]) == text


@pytest.mark.parametrize("text,protected", [
    ("PIN 1234", False),
    ("PIN 1234, карта 4111 1111 1111 1111", True),
    ("Карта 4111 1111 1111 1111, PIN 1234", True),
    ("PIN 1234. Карта 4111 1111 1111 1111", False),
    ("PIN 1234; карта 4111 1111 1111 1111", False),
    ("PIN 1234\nКарта 4111 1111 1111 1111", False),
    ("PIN 1234, " + "текст " * 40 + "карта 4111 1111 1111 1111", False),
])
def test_combination_is_local_and_explained(text, protected):
    gateway = Gateway(BaselineDetector(), MemoryVault())
    policy = Policy(version="1", detect_types=ALL,
                    combination_rules=[CombinationRule(target="PIN", requires={"CARD"}, max_distance=128)])
    result = gateway.mask("a", text, policy)
    decision = next(d for d in result["receipt"]["decisions"] if d["type"] == "PIN")
    assert decision["protected"] is protected
    assert ("1234" not in result["text"]) is protected
    assert "1234" not in json.dumps(result["receipt"])
    assert gateway.restore("a", result["session_id"], result["text"]) == text


def test_mixed_irreversible_mode_does_not_store_redacted_value():
    vault = MemoryVault()
    gateway = Gateway(BaselineDetector(), vault)
    policy = Policy(version="1", detect_types=ALL, mode_by_type={"PIN": "redact"})
    result = gateway.mask("a", "PIN 1234; email a@example.org", policy)
    assert "1234" not in json.dumps(vault.get("a", result["session_id"]))
    assert result["receipt"]["irreversible_fragments"] == 1
    assert gateway.restore("a", result["session_id"], result["text"]) == "PIN [REDACTED:PIN]; email a@example.org"


@pytest.mark.parametrize("options", [
    {"mode_by_type": {"UNKNOWN": "redact"}},
    {"mode_by_type": {"PIN": "unknown-mode"}},
    {"combination_rules": [{"target": "PIN", "requires": ["PIN"]}]},
    {"combination_rules": [{"target": "PIN", "requires": ["UNKNOWN"]}]},
])
def test_policy_rejects_invalid_transformations(options):
    with pytest.raises(ValueError):
        Policy(version="1", detect_types=ALL, **options)


def test_evaluator_stays_reversible_with_irreversible_consumer():
    policy = Policy(version="1", detect_types={"EMAIL"}, mode_by_type={"EMAIL": "redact"})
    with TestClient(create_app({"a": policy}, {"a": "a" * 32})) as client:
        source = "PIN 1234; a@example.org"
        body = {"payload_id": "one", "payload": source}
        masked = client.post("/process", json=body).json()["result"]
        assert "1234" not in masked and "a@example.org" not in masked
        assert client.post("/process", json={**body, "payload": masked}).json() == {"result": source}


def test_cache_is_bounded_private_policy_aware_and_not_a_mask_cache(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.detection_cache.time.monotonic", lambda: now[0])
    cache = CachedDetector(BaselineDetector(), capacity=1, ttl=1)
    text = "a@example.org"
    expected = cache.detect(text, {"EMAIL"})
    first = cache.detect(text, {"EMAIL"})
    first.clear()
    assert cache.detect(text, {"EMAIL"}) == expected
    assert text not in repr(cache.entries)
    assert cache.detect(text, set()) == []
    assert len(cache.entries) == 1
    now[0] = 2
    cache.detect(text, set())
    assert cache.stats()["misses"] == 3
    cache.detect("x" * 20_000, ALL)
    assert cache.stats()["bypasses"] == 1


def test_concurrent_cache_consistency():
    cache = CachedDetector(BaselineDetector(), capacity=4)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: cache.detect("a@example.org", ALL), range(40)))
    assert all(result == results[0] for result in results)
    assert len(cache.entries) == 1


def test_inline_lane_does_not_wait_on_worker_lock_or_decrypt_large_entry():
    vault = MemoryVault()
    service = ProcessService(Gateway(BaselineDetector(), MemoryVault()), Policy(version="1", detect_types=ALL), vault)
    identifier = "one"
    key = hashlib.sha256(identifier.encode()).hexdigest()
    lock = service.locks[int(key[:2], 16)]
    with lock, pytest.raises(VaultError, match="process_busy"):
        service.process(identifier, "a@example.org", blocking=False)
    # One huge sensitive value keeps even a compact record large. Ordinary
    # long no-PII text now has a tiny record, so its short conflict is safe inline.
    service.process(identifier, "a" * 40_000 + "@example.org")
    assert not service.can_inline(identifier, "small conflicting text")
    with pytest.raises(VaultError, match="process_busy"):
        service.process(identifier, "small conflicting text", blocking=False)


def test_new_type_from_literal_configuration_and_isolation():
    rule = FieldRule(kind="CUSTOMER_ID", labels=["Код клиента", "Client (ID)"])
    detector = BaselineDetector([rule])
    for text in ["Код клиента: ABC-123", "Client (ID): ABC-123"]:
        spans = detector.detect(text, {"CUSTOMER_ID"})
        assert [text[s.start:s.end] for s in spans] == ["ABC-123"]
    assert "CUSTOMER_ID" not in BaselineDetector().supported_types
    with pytest.raises(ValueError, match="duplicate_detector_type"):
        BaselineDetector([FieldRule(kind="EMAIL", labels=["email"])])
    policy = Policy(version="1", detect_types={"CUSTOMER_ID"})
    with TestClient(create_app({"a": policy}, {"a": "a" * 32}, field_rules=[rule])) as client:
        response = client.post("/v1/mask", headers={"X-System-ID": "a", "X-API-Key": "a" * 32},
                               json={"text": "Код клиента: ABC-123"})
        assert response.status_code == 200
        assert response.json()["detected_types"] == {"CUSTOMER_ID": 1}


def test_completed_pairs_keep_retries_then_release_capacity(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    vault = MemoryVault(capacity=1)
    service = ProcessService(Gateway(BaselineDetector(), MemoryVault()), Policy(version="1", detect_types=ALL),
                             vault, completed_ttl=60)
    masked, _ = service.process("one", "a@example.org")
    assert service.process("one", masked)[0] == "a@example.org"
    now[0] = 59
    assert service.process("one", masked)[0] == "a@example.org"
    now[0] = 60
    service.process("two", "b@example.org")
    assert len(vault.entries) == 1


def test_old_heap_deadline_cannot_delete_reused_session(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    vault = MemoryVault()
    vault.put("a", {"revision": 1}, 100, session="same")
    vault.shorten_ttl("a", "same", 10)
    now[0] = 11
    vault.put("a", {"revision": 2}, 300, session="same")
    now[0] = 101
    assert vault.get("a", "same") == {"revision": 2}
    assert vault.used_bytes == sum(len(entry[2]) for entry in vault.entries.values())


def test_completed_heap_nodes_remain_bounded(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    vault = MemoryVault(capacity=2)
    for index in range(150):
        key = vault.put("a", {}, 3600)
        vault.shorten_ttl("a", key, 1)
        now[0] += 2
    assert len(vault.expirations) <= 64


def test_optional_policy_must_not_bypass_external_egress_guard(tmp_path):
    import httpx

    from alpha_privacy.alfagen import AlfaGenProvider
    key = tmp_path / "key"
    key.write_text("synthetic-test-key")
    called = []
    provider = AlfaGenProvider(str(key), transport=httpx.MockTransport(lambda request: called.append(request)))
    policy = Policy(version="1", detect_types=ALL,
                    combination_rules=[CombinationRule(target="PIN", requires={"CARD"})])
    with TestClient(create_app({"a": policy}, {"a": "a" * 32}, provider, allow_alfagen=True)) as client:
        response = client.post("/v1/proxy", headers={"X-System-ID": "a", "X-API-Key": "a" * 32},
                               json={"text": "PIN 1234"})
        assert response.status_code == 422
        assert called == []


def test_large_lane_does_not_block_small_request():
    import asyncio
    from unittest.mock import patch

    import httpx
    entered, release = threading.Event(), threading.Event()
    original = ProcessService.process

    def delayed(self, payload_id, payload, **kwargs):
        if payload_id == "large":
            entered.set()
            assert release.wait(5), "Large request did not run in the worker pool"
        return original(self, payload_id, payload, **kwargs)

    async def run():
        app = create_app({"a": Policy(version="1", detect_types=ALL)}, {"a": "a" * 32})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            large = asyncio.create_task(client.post("/process", json={"payload_id": "large", "payload": "word " * 2000}))
            try:
                assert await asyncio.to_thread(entered.wait, 3)
                small = await asyncio.wait_for(client.post("/process", json={"payload_id": "small", "payload": "a@example.org"}), 2)
                assert small.status_code == 200
            finally:
                release.set()
                assert (await large).status_code == 200
    with patch.object(ProcessService, "process", delayed):
        asyncio.run(run())
