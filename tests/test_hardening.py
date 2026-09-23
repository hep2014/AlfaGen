import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from alpha_privacy.api import create_app
from alpha_privacy.core import BaselineDetector, Policy
from alpha_privacy.providers import LocalEcho

KEY = "test-key-not-for-deployment".ljust(40, "x")
HEADERS = {"X-System-ID": "test", "X-API-Key": KEY}


def client_for(provider=None):
    return TestClient(create_app({"test": Policy(version="test-v1", detect_types=BaselineDetector.supported_types)},
                                 {"test": KEY}, provider))


@pytest.mark.parametrize("kind,text,value", [
    ("INN", "ИНН: 123456789012", "123456789012"),
    ("INN", "инн 1234567890", "1234567890"),
    ("CARD", "Номер банковской карты: 4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("CVV", "CVV-код: 123", "123"),
    ("PIN", "пин-код карты: 1234", "1234"),
    ("PASSPORT_RU", "ПАСПОРТ РФ: серия 12 34 номер 567890", "серия 12 34 номер 567890"),
    ("PASSPORT_RU", "паспорт 1234567890", "1234567890"),
    ("DEPARTMENT_CODE", "код подразделения: 123-456", "123-456"),
    ("DRIVER_LICENSE", "Водительское удостоверение: 12 34 567890", "12 34 567890"),
])
def test_contextual_categories_roundtrip(kind, text, value):
    response = client_for().post("/v1/proxy", headers=HEADERS, json={"text": text})
    assert response.status_code == 200
    result = response.json()
    assert result["answer"] == text
    assert result["masked"]["detected_types"] == {kind: 2 if "серия" in value else 1}
    assert value not in result["masked"]["text"]


@pytest.mark.parametrize("text", ["В очереди 123 человека", "Артикул 1234567890", "Пинг 1234 мс", "инновация 1234567890"])
def test_numbers_without_sensitive_context(text):
    assert BaselineDetector().detect(text, BaselineDetector.supported_types) == []


def test_correlated_audit_for_all_failures_and_no_attacker_data(caplog):
    client = client_for()
    secret = "sensitive@example.org"
    with caplog.at_level("INFO", logger="alpha_privacy.audit"):
        responses = [
            client.post("/v1/mask?secret=" + secret, headers={"X-Request-ID": secret}, json={"text": secret}),
            client.post("/v1/mask", headers=HEADERS, json={"text": {"value": secret}}),
            client.post("/v1/mask", headers=HEADERS, json={"text": secret}),
            client.get("/" + secret),
        ]
    assert [r.status_code for r in responses] == [401, 422, 200, 404]
    records = [json.loads(r.message) for r in caplog.records if r.name == "alpha_privacy.audit"]
    ids = {r.headers["x-request-id"] for r in responses}
    assert len(ids) == 4
    assert all(len(i) == 32 for i in ids)
    assert {r["request_id"] for r in records} == ids
    assert sum(r["event"] == "request_finished" for r in records) == 4
    assert secret not in caplog.text and KEY not in caplog.text
    metrics = client.get("/metrics", headers=HEADERS).text
    assert 'privacy_http_requests_total{operation="mask",status_code="401"} 1.0' in metrics


def test_parallel_request_context_isolation(caplog):
    client = client_for()
    with caplog.at_level("INFO", logger="alpha_privacy.audit"), ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: client.post("/v1/proxy", headers=HEADERS, json={"text": "demo@example.org"}), range(8)))
    ids = {r.headers["x-request-id"] for r in responses}
    assert len(ids) == 8
    records = [json.loads(r.message) for r in caplog.records if r.name == "alpha_privacy.audit"]
    for rid in ids:
        events = [r["event"] for r in records if r["request_id"] == rid]
        assert events.count("request_started") == events.count("request_finished") == 1
        assert "detection" in events


def test_body_limit_before_json_validation():
    response = client_for().post("/v1/mask", headers=HEADERS, content=b"x" * 32_000_001)
    assert response.status_code == 413
    assert response.json() == {"detail": "request_too_large"}
    assert "x-request-id" in response.headers


def test_provider_only_receives_protected_text():
    class Spy(LocalEcho):
        def generate(self, protected_text):
            assert "demo@example.org" not in protected_text
            assert "[[PD:" in protected_text
            return "Ответ: " + protected_text
    response = client_for(Spy()).post("/v1/proxy", headers=HEADERS, json={"text": "demo@example.org"})
    assert response.json()["answer"] == "Ответ: demo@example.org"


def test_provider_exception_does_not_leak(caplog):
    class Broken(LocalEcho):
        def generate(self, protected_text):
            raise ValueError("provider-key-and-private@example.org")
    with caplog.at_level("INFO", logger="alpha_privacy.audit"):
        response = client_for(Broken()).post("/v1/proxy", headers=HEADERS, json={"text": "demo@example.org"})
    assert response.status_code == 503
    assert response.json() == {"detail": "processing_unavailable"}
    assert "private@example.org" not in caplog.text + response.text


@pytest.mark.parametrize("output", ["new@example.org", "[[PD:foreign:EMAIL:1]]", "[[PD:broken"])
def test_unsafe_provider_response_is_blocked(output):
    class Unsafe(LocalEcho):
        def generate(self, protected_text):
            return output
    response = client_for(Unsafe()).post("/v1/proxy", headers=HEADERS, json={"text": "demo@example.org"})
    assert response.status_code == 422
    assert output not in response.text


def test_external_provider_is_not_accidentally_enabled():
    class External(LocalEcho):
        local_only = False
    with pytest.raises(ValueError, match="External LLM"):
        client_for(External())
