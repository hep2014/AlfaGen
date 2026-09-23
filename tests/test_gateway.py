
import pytest
from fastapi.testclient import TestClient

from alpha_privacy.api import create_app
from alpha_privacy.core import (
    BaselineDetector,
    Gateway,
    MemoryVault,
    Policy,
    VaultError,
)


@pytest.fixture
def setup():
    policies = {name: Policy(version="1", detect_types={"EMAIL", "PHONE"}, restore_enabled=name != "analytics")
                for name in ["support", "other", "analytics"]}
    keys = {name: name.ljust(32, "x") for name in policies}
    client = TestClient(create_app(policies, keys))
    def headers(name="support"):
        return {"X-System-ID": name, "X-API-Key": keys[name]}
    return client, headers


def test_exact_roundtrip_and_no_cleartext_in_mask(setup, caplog):
    client, headers = setup
    original = "Контакт TEST@example.org, +7 (999) 123-45-67; ещё TEST@example.org.\n"
    with caplog.at_level("INFO", logger="alpha_privacy.audit"):
        response = client.post("/v1/demo/roundtrip", headers=headers(), json={"text": original})
    assert response.status_code == 200
    data = response.json()
    assert data["answer"] == original
    assert "TEST@example.org" not in data["masked"]["text"]
    assert "123-45-67" not in data["masked"]["text"]
    assert "TEST@example.org" not in caplog.text
    assert "123-45-67" not in caplog.text
    assert data["masked"]["detected_types"] == {"EMAIL": 2, "PHONE": 1}


def test_isolation_and_disabled_restore(setup):
    client, headers = setup
    masked = client.post("/v1/mask", headers=headers(), json={"text": "x@example.org"}).json()
    payload = {k: masked[k] for k in ["text", "session_id"]}
    assert client.post("/v1/restore", headers=headers("other"), json=payload).status_code == 404
    assert client.post("/v1/restore", headers=headers("analytics"), json=payload).status_code == 403
    assert client.post("/v1/mask", json={"text": "x"}).status_code in [401, 422]


def test_foreign_token_rejected(setup):
    client, headers = setup
    first, second = [client.post("/v1/mask", headers=headers(), json={"text": "x@example.org"}).json() for _ in range(2)]
    assert client.post("/v1/restore", headers=headers(), json={"text": second["text"], "session_id": first["session_id"]}).status_code == 422


def test_validation_does_not_echo_input(setup):
    client, headers = setup
    response = client.post("/v1/mask", headers=headers(), json={"text": {"secret": "x@example.org"}})
    assert response.status_code == 422
    assert "example.org" not in response.text
    assert client.post("/v1/mask", headers=headers(), json={"text": "[[PD:forged]]"}).status_code == 422


def test_vault_encryption_capacity_expiry(monkeypatch):
    now = [1.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    vault = MemoryVault(capacity=1)
    session = vault.put("a", {"value": "private@example.org"}, 2)
    assert b"private@example.org" not in vault.entries[session][2]
    with pytest.raises(VaultError):
        vault.put("a", {}, 2)
    now[0] = 4
    with pytest.raises(VaultError):
        vault.get("a", session)
    vault.put("a", {}, 2)


def test_fail_closed_on_capacity_and_disabled_system(setup):
    policy = Policy(version="1", detect_types={"EMAIL"})
    service = Gateway(BaselineDetector(), MemoryVault(capacity=0))
    with pytest.raises(VaultError):
        service.mask("a", "x@example.org", policy)
    policy.enabled = False
    client = TestClient(create_app({"a": policy}, {"a": "x" * 32}))
    assert client.post("/v1/mask", headers={"X-System-ID": "a", "X-API-Key": "x" * 32}, json={"text": "x@example.org"}).status_code == 403


def test_metrics_and_unsupported_policy(setup):
    client, headers = setup
    client.post("/v1/mask", headers=headers(), json={"text": "x@example.org"})
    response = client.get("/metrics", headers=headers())
    assert "privacy_operation_seconds" in response.text
    assert "x@example.org" not in response.text
    with pytest.raises(ValueError):
        create_app({"a": Policy(version="1", detect_types={"UNKNOWN_TYPE"})}, {"a": "x" * 32})
