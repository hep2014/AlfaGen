import json

import httpx
import pytest
from fastapi.testclient import TestClient

from alpha_privacy.alfagen import MODEL, AlfaGenProvider, ProviderUnavailable
from alpha_privacy.api import create_app, from_env
from alpha_privacy.core import BaselineDetector, Policy
from alpha_privacy.sandbox import compare_policies
from alpha_privacy.synthetic import generate


def test_policy_regression_detected_per_example():
    rows = [row for row in generate() if row["split"] == "test"]
    kinds = BaselineDetector.supported_types
    result = compare_policies(rows, kinds, kinds - {"PERSON"})
    assert not result["eligible_on_this_dataset"]
    assert result["new_misses"] > 0
    assert "test-private-person" in result["regression_example_ids"]
    improved = compare_policies(rows, kinds - {"PERSON"}, kinds)
    assert improved["eligible_on_this_dataset"]
    assert improved["fixed_misses"] > 0


def test_sandbox_does_not_mutate_live_policy():
    policy = Policy(version="1", detect_types=BaselineDetector.supported_types)
    client = TestClient(create_app({"test": policy}, {"test": "x" * 40}))
    headers = {"X-System-ID": "test", "X-API-Key": "x" * 40}
    result = client.post("/v1/policies/compare", headers=headers, json={"detect_types": []})
    assert result.status_code == 200
    assert not result.json()["eligible_on_this_dataset"]
    masked = client.post("/v1/mask", headers=headers, json={"text": "ФИО: Иван Фантазиев"})
    assert masked.json()["detected_types"] == {"PERSON": 1}


def test_alfagen_contract(tmp_path):
    key = tmp_path / "key"
    key.write_text("synthetic-secret", encoding="utf-8")
    def handle(request):
        assert str(request.url) == "https://alfagen.alfabank.ru/continue-dev/chat/completions"
        assert request.headers["Authorization"] == "Bearer synthetic-secret"
        body = json.loads(request.content)
        assert body["model"] == MODEL
        assert body["stream"] is False
        return httpx.Response(200, json={"choices": [{"message": {"content": "Ответ [[PD:token]]"}}]})
    provider = AlfaGenProvider(str(key), transport=httpx.MockTransport(handle))
    assert provider.generate("[[PD:token]]") == "Ответ [[PD:token]]"


def test_alfagen_accepts_api_key_directly():
    def handle(request):
        assert request.headers["Authorization"] == "Bearer env-secret"
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = AlfaGenProvider(api_key="env-secret", transport=httpx.MockTransport(handle))
    assert provider.generate("safe") == "ok"


def test_from_env_uses_alfagen_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "alfagen")
    monkeypatch.setenv("ALFAGEN_API_KEY", "env-secret")
    monkeypatch.delenv("ALFAGEN_KEY_FILE", raising=False)
    monkeypatch.setenv("GATEWAY_API_KEYS", json.dumps({"support-demo": "x" * 40}))
    app = from_env()
    with TestClient(app) as client:
        assert client.get("/health/live").json()["mode"] == "alfagen-deepseek-flash"


@pytest.mark.parametrize("status,body", [(401, b"secret"), (429, b"secret"), (302, b"secret"), (200, b"not-json"), (200, b'{"choices":[]}')])
def test_alfagen_errors_are_sanitized(tmp_path, status, body):
    key = tmp_path / "key"
    key.write_text("synthetic-secret", encoding="utf-8")
    provider = AlfaGenProvider(str(key), transport=httpx.MockTransport(lambda _: httpx.Response(status, content=body)))
    with pytest.raises(ProviderUnavailable, match="^alfagen_unavailable$"):
        provider.generate("safe")


def test_alfagen_rejects_untrusted_endpoint(tmp_path):
    with pytest.raises(ValueError, match="invalid_alfagen_url"):
        AlfaGenProvider(str(tmp_path / "missing"), base_url="https://example.org/")


def test_alfagen_proxy_and_egress_guard(tmp_path):
    key = tmp_path / "key"
    key.write_text("synthetic-secret", encoding="utf-8")
    calls = []
    def handle(request):
        text = json.loads(request.content)["messages"][-1]["content"]
        assert "example.org" not in text
        calls.append(text)
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})
    provider = AlfaGenProvider(str(key), transport=httpx.MockTransport(handle))
    policies = {"safe": Policy(version="1", detect_types=BaselineDetector.supported_types),
                "unsafe": Policy(version="1", detect_types=set())}
    client = TestClient(create_app(policies, {"safe": "a" * 40, "unsafe": "b" * 40}, provider, allow_alfagen=True))
    response = client.post("/v1/proxy", headers={"X-System-ID": "safe", "X-API-Key": "a" * 40}, json={"text": "demo@example.org"})
    assert response.status_code == 200
    assert response.json()["answer"] == "demo@example.org"
    blocked = client.post("/v1/proxy", headers={"X-System-ID": "unsafe", "X-API-Key": "b" * 40}, json={"text": "demo@example.org"})
    assert blocked.status_code == 422
    assert len(calls) == 1


def test_sandbox_logs_summary_not_each_fixture(caplog):
    rows = [row for row in generate() if row["split"] == "test"]
    with caplog.at_level("INFO", logger="alpha_privacy.audit"):
        compare_policies(rows, BaselineDetector.supported_types, set())
    events = [json.loads(r.message)["event"] for r in caplog.records if r.name == "alpha_privacy.audit"]
    assert events == ["policy_comparison"]
