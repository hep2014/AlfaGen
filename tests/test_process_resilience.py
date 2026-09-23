import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from alpha_privacy.api import create_app
from alpha_privacy.core import (
    BaselineDetector,
    Gateway,
    MemoryVault,
    Policy,
    SQLiteVault,
    VaultError,
)
from alpha_privacy.process import ProcessService

POLICY = Policy(version="regression", detect_types=BaselineDetector.supported_types)
KEY = "test-only".ljust(32, "x")


def make_app(**kwargs):
    return create_app({"test": POLICY}, {"test": KEY}, **kwargs)


def post(client, text, identifier="one"):
    return client.post("/process", json={"payload": text, "payload_id": identifier})


@pytest.mark.parametrize("text", [
    "test@example.org", "Без персональных данных 🦊\n", "Повтор a@example.org и a@example.org.",
    "Клиент Иванов Иван; клиент Петров Пётр; паспорт серия 45 09 номер 123456.",
])
def test_pair_retries_and_exact_unicode(text):
    with TestClient(make_app()) as client:
        masked = post(client, text).json()["result"]
        for _ in range(3):
            assert post(client, text).json() == {"result": masked}
            assert post(client, masked).json() == {"result": text}


def test_conflicts_and_tokens_do_not_pass_through():
    with TestClient(make_app()) as client:
        masked = post(client, "a@example.org").json()["result"]
        assert post(client, "b@example.org").status_code == 409
        assert post(client, masked + " changed").status_code == 409
        assert post(client, masked, "different").status_code == 422
        assert post(client, "[[PD:broken", "new").status_code == 422
        assert post(client, masked).json()["result"] == "a@example.org"


def test_capacity_keeps_live_pairs_and_metrics():
    with TestClient(make_app(process_capacity=1)) as client:
        masked = post(client, "a@example.org").json()["result"]
        response = post(client, "b@example.org", "two")
        assert response.status_code == 429 and response.headers["retry-after"] == "1"
        assert post(client, masked).json()["result"] == "a@example.org"
        metrics = client.get("/metrics", headers={"X-System-ID": "test", "X-API-Key": KEY}).text
        assert 'privacy_http_requests_total{operation="process",status_code="429"} 1.0' in metrics
        assert 'privacy_operation_seconds_count{operation="process"} 3.0' in metrics


def test_byte_capacity_rejection():
    with TestClient(make_app(process_max_bytes=1)) as client:
        assert post(client, "a@example.org").status_code == 429


def test_oversized_new_text_does_not_reserve_id():
    with TestClient(make_app()) as client:
        assert post(client, "x" * 1_000_001).status_code == 422
        assert post(client, "a@example.org").status_code == 200


def test_process_validation_and_audit_do_not_echo_data(caplog):
    secret = "private@example.org"
    with TestClient(make_app()) as client, caplog.at_level("INFO", logger="alpha_privacy.audit"):
        assert client.post("/process", json={"payload": {"private": secret}, "payload_id": secret}).status_code == 422
        assert post(client, secret).status_code == 200
        assert post(client, "other@example.org").status_code == 409
    assert secret not in caplog.text and "other@example.org" not in caplog.text


def test_expiry_and_encryption(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    vault = MemoryVault(capacity=1)
    service = ProcessService(Gateway(BaselineDetector(), MemoryVault()), POLICY, vault)
    masked, _ = service.process("one", "private@example.org")
    assert b"private@example.org" not in next(iter(vault.entries.values()))[2]
    now[0] = POLICY.session_ttl_seconds
    service.process("two", "other@example.org")
    with pytest.raises(ValueError, match="reserved_token_syntax"):
        service.process("one", masked)
    assert len(vault.entries) == len(vault.expirations) == 1
    assert vault.used_bytes == sum(len(e[2]) for e in vault.entries.values())


def test_vault_different_ttls_and_owner_isolation(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    vault = MemoryVault()
    long = vault.put("a", {}, 20)
    short = vault.put("a", {}, 1)
    now[0] = 1.0
    assert vault.get("a", long) == {}
    with pytest.raises(VaultError):
        vault.get("a", short)
    with pytest.raises(VaultError):
        vault.get("b", long)


def test_simultaneous_same_id_has_one_mask():
    class SlowDetector(BaselineDetector):
        def detect(self, text, kinds):
            time.sleep(0.01)
            return super().detect(text, kinds)
    service = ProcessService(Gateway(SlowDetector(), MemoryVault()), POLICY, MemoryVault())
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: service.process("same", "a@example.org")[0], range(40)))
    assert len(set(results)) == 1
    assert len(service.vault.entries) == 1


def test_200_concurrent_http_pairs():
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=make_app()), base_url="http://test") as client:
            async def pair(i):
                original = f"person-{i}@example.org"
                first = await client.post("/process", json={"payload_id": str(i), "payload": original})
                assert first.status_code == 200
                masked = first.json()["result"]
                assert original not in masked
                second = await client.post("/process", json={"payload_id": str(i), "payload": masked})
                assert second.status_code == 200 and second.json()["result"] == original
            await asyncio.gather(*(pair(i) for i in range(200)))
    asyncio.run(run())


def test_large_text_and_expanded_mask_roundtrip():
    # 100,000 space-delimited words, not a claim about a particular LLM tokenizer.
    original = "слово " * 99_999 + "a@example.org"
    dense = "a@b.ru " * 22_000
    with TestClient(make_app()) as client:
        for i, text in enumerate((original, dense)):
            masked = post(client, text, str(i))
            assert masked.status_code == 200
            assert post(client, masked.json()["result"], str(i)).json() == {"result": text}
        headers = {"X-System-ID": "test", "X-API-Key": KEY}
        masked = client.post("/v1/mask", headers=headers, json={"text": dense}).json()
        assert len(masked["text"]) > 1_000_000
        restored = client.post("/v1/restore", headers=headers,
                               json={"text": masked["text"], "session_id": masked["session_id"]})
        assert restored.json() == {"text": dense}


def test_sqlite_vault_keeps_pairs_across_service_instances(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "shared-vault.sqlite3"
    policy = Policy(version="shared", detect_types=BaselineDetector.supported_types)
    first = ProcessService(Gateway(BaselineDetector(), MemoryVault()), policy,
                           SQLiteVault(path, capacity=10, key=key))
    second = ProcessService(Gateway(BaselineDetector(), MemoryVault()), policy,
                            SQLiteVault(path, capacity=10, key=key))
    original = "shared@example.org"
    masked, _ = first.process("shared-id", original)
    assert second.process("shared-id", original)[0] == masked
    assert second.process("shared-id", masked)[0] == original
    first.vault.close()
    second.vault.close()


def test_sqlite_vault_race_returns_one_winning_mask(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "race.sqlite3"
    policy = Policy(version="shared", detect_types=BaselineDetector.supported_types)
    services = [
        ProcessService(Gateway(BaselineDetector(), MemoryVault()), policy,
                       SQLiteVault(path, capacity=10, key=key))
        for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda service: service.process("race-id", "race@example.org")[0], services))
    assert results[0] == results[1]
    assert services[0].vault.count() == 1
    for service in services:
        service.vault.close()
