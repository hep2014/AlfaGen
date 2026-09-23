
import pytest
from fastapi.testclient import TestClient

from alpha_privacy.api import create_app
from alpha_privacy.core import BaselineDetector, Gateway, MemoryVault, Policy
from alpha_privacy.field_rules import FieldRule
from alpha_privacy.policy_preview import preview_policy

ALL = BaselineDetector.supported_types
HEADERS = {"X-System-ID": "client", "X-API-Key": "x" * 32}


def policy(**changes):
    return Policy(version="current", detect_types=ALL, **changes)


def post_preview(client, text, candidate, headers=HEADERS):
    return client.post("/v1/policies/preview", headers=headers,
                       json={"text": text, "candidate": candidate.model_dump(mode="json")})


def test_excluding_a_type_reports_only_newly_unprotected_positions_without_values(caplog):
    current = Policy(version="current", detect_types={"EMAIL"})
    candidate = Policy(version="private-version@example.org", detect_types=set())
    text = "Email private.person@example.org; PIN 9876"
    with TestClient(create_app({"client": current}, {"client": "x" * 32})) as client, caplog.at_level("INFO", logger="alpha_privacy.audit"):
        response = post_preview(client, text, candidate)
    assert response.status_code == 200
    result = response.json()
    assert result["coverage_basis"] == "same-detector-findings-only"
    assert result["quality_guarantee"] is False
    assert result["candidate"]["excluded_types"] == ["EMAIL", "PIN"]
    assert result["candidate"]["protected_fragments"] == 0
    assert result["comparison"]["new_misses"] == [
        {"start": text.index("private.person"), "end": text.index(";"), "type": "EMAIL"}
    ]
    assert result["comparison"]["new_missed_characters"] == len("private.person@example.org")
    for secret in [text, "private.person@example.org", "private-version@example.org", "9876"]:
        assert secret not in response.text
        assert secret not in caplog.text


@pytest.mark.parametrize("text,protected", [
    ("PIN 1234", False),
    ("PIN 1234, карта 4111 1111 1111 1111", True),
    ("PIN 1234. Карта 4111 1111 1111 1111", False),
])
def test_conditional_pin_uses_the_real_combination_decisions(text, protected):
    candidate = policy(combination_rules=[{"target": "PIN", "requires": {"CARD"}, "max_distance": 128}])
    detector = BaselineDetector()
    result = preview_policy(text, policy(), candidate, detector)
    decision = next(item for item in result["candidate"]["decisions"] if item["type"] == "PIN")
    assert decision["protected"] is protected
    assert decision["reason"] == ("combination_present" if protected else "combination_missing")
    assert result["comparison"]["new_missed_fragments"] == int(not protected)
    actual = Gateway(detector, MemoryVault()).transform(text, candidate)[3]
    assert [{key: value for key, value in item.items() if key != "restorable"}
            for item in result["candidate"]["decisions"]] == actual


@pytest.mark.parametrize("restore_enabled,mode,irreversible", [
    (True, "token", 0), (True, "redact", 1), (False, "token", 1), (False, "redact", 1),
])
def test_irreversibility_includes_redaction_and_disabled_restoration(restore_enabled, mode, irreversible):
    candidate = policy(restore_enabled=restore_enabled, mode_by_type={"EMAIL": mode}, session_ttl_seconds=17)
    result = preview_policy("private@example.org", policy(), candidate, BaselineDetector())
    after = result["candidate"]
    assert after["protected_fragments"] == 1
    assert after["irreversible_fragments"] == irreversible
    assert after["decisions"][0]["mode"] == mode
    assert after["decisions"][0]["restorable"] is (irreversible == 0)
    assert after["session_ttl_seconds"] == 17
    assert result["comparison"]["new_misses"] == []


def test_authorization_selects_current_policy_and_prevents_tenant_spoofing():
    policies = {"client": Policy(version="a", detect_types={"EMAIL"}),
                "other": Policy(version="b", detect_types={"PIN"}),
                "disabled": policy(enabled=False)}
    keys = {"client": "x" * 32, "other": "y" * 32, "disabled": "z" * 32}
    text = "private@example.org; PIN 1234"
    candidate = Policy(version="candidate", detect_types=set())
    with TestClient(create_app(policies, keys)) as client:
        for owner, expected in [("client", "EMAIL"), ("other", "PIN")]:
            response = post_preview(client, text, candidate,
                                    {"X-System-ID": owner, "X-API-Key": keys[owner]})
            assert response.status_code == 200
            assert [decision["type"] for decision in response.json()["current"]["decisions"]] == [expected]
            assert [span["type"] for span in response.json()["comparison"]["new_misses"]] == [expected]
        assert post_preview(client, text, candidate, {}).status_code == 401
        assert post_preview(client, text, candidate, {**HEADERS, "X-System-ID": "other"}).status_code == 401
        assert post_preview(client, text, candidate,
                            {"X-System-ID": "disabled", "X-API-Key": keys["disabled"]}).status_code == 403
        assert client.post("/v1/policies/preview", headers=HEADERS,
                           json={"text": text, "candidate": candidate.model_dump(mode="json"),
                                 "owner": "other"}).status_code == 422


def test_disabled_candidate_is_reported_as_denied_not_as_safe_masking():
    result = preview_policy("private@example.org", policy(), policy(enabled=False), BaselineDetector())
    assert result["candidate"]["status"] == "system_disabled"
    assert result["candidate"]["decisions"] == []
    assert result["candidate"]["unprotected_reference_fragments"] is None
    assert result["comparison"]["comparable"] is False
    assert result["comparison"]["new_misses"] is None
    assert result["comparison"]["new_missed_fragments"] is None


def test_custom_rule_overlaps_are_recomputed_and_partial_gaps_are_exact():
    rule = FieldRule(kind="CUSTOMER_ID", labels=["Код"])
    current = Policy(version="current", detect_types={"EMAIL"})
    candidate = Policy(version="candidate", detect_types={"CUSTOMER_ID"})
    text = "Код: abc@example.org"
    with TestClient(create_app({"client": current}, {"client": "x" * 32}, field_rules=[rule])) as client:
        response = post_preview(client, text, candidate)
    assert response.status_code == 200
    result = response.json()
    assert result["reference_findings"] == [{"start": 5, "end": len(text), "type": "EMAIL"}]
    assert result["candidate"]["decisions"][0]["type"] == "CUSTOMER_ID"
    assert result["candidate"]["decisions"][0]["end"] == text.index("@")
    assert result["comparison"]["new_misses"] == [
        {"start": text.index("@"), "end": len(text), "type": "EMAIL"}
    ]
    improved = preview_policy(text, candidate, current, BaselineDetector([rule]))
    assert improved["comparison"]["new_misses"] == []
    assert improved["comparison"]["fixed_misses"] == result["comparison"]["new_misses"]


def test_custom_rule_is_part_of_reference_when_excluded_by_candidate():
    rule = FieldRule(kind="CUSTOMER_ID", labels=["Код клиента"])
    detector = BaselineDetector([rule])
    current = Policy(version="current", detect_types=detector.supported_types)
    candidate = Policy(version="candidate", detect_types=ALL)
    result = preview_policy("Код клиента: ABC-987", current, candidate, detector)
    assert result["candidate"]["excluded_types"] == ["CUSTOMER_ID"]
    assert result["comparison"]["new_misses"] == [{"start": 13, "end": 20, "type": "CUSTOMER_ID"}]


def test_preview_has_no_vault_provider_transformation_or_policy_side_effects(monkeypatch):
    class UnusedProvider:
        local_only = True
        name = "must-not-be-called"

        def generate(self, _):
            raise AssertionError("preview called provider")

    def forbidden(*args, **kwargs):
        raise AssertionError("preview performed persistence or token generation")

    current = policy()
    snapshot = current.model_dump(mode="json")
    with TestClient(create_app({"client": current}, {"client": "x" * 32}, UnusedProvider())) as client:
        with monkeypatch.context() as guard:
            guard.setattr(MemoryVault, "put", forbidden)
            guard.setattr(MemoryVault, "get", forbidden)
            guard.setattr(Gateway, "transform", forbidden)
            response = post_preview(client, "private@example.org", Policy(version="draft", detect_types=set()))
        assert response.status_code == 200
        assert current.model_dump(mode="json") == snapshot
        result = client.post("/v1/mask", headers=HEADERS, json={"text": "private@example.org"}).json()
        assert result["detected_types"] == {"EMAIL": 1}
        metrics = client.get("/metrics", headers=HEADERS).text
        assert 'operation="policy_preview"' in metrics


@pytest.mark.parametrize("text,status", [("x" * 16_384, 200), ("x" * 16_385, 422), ("", 422)])
def test_preview_text_size_limit(text, status):
    with TestClient(create_app({"client": policy()}, {"client": "x" * 32})) as client:
        response = post_preview(client, text, policy())
        assert response.status_code == status


@pytest.mark.parametrize("candidate", [
    {"version": "draft", "detect_types": ["UNKNOWN"]},
    {"version": "draft", "detect_types": ["EMAIL"], "mode_by_type": {"EMAIL": "unknown"}},
    {"version": "draft", "detect_types": ["PIN"],
     "combination_rules": [{"target": "PIN", "requires": ["CARD"]}]},
])
def test_invalid_candidates_are_sanitized(candidate):
    with TestClient(create_app({"client": policy()}, {"client": "x" * 32})) as client:
        response = client.post("/v1/policies/preview", headers=HEADERS,
                               json={"text": "private@example.org", "candidate": candidate})
    assert response.status_code == 422
    assert "private@example.org" not in response.text


def test_reserved_tokens_are_rejected_as_in_real_transformation():
    with TestClient(create_app({"client": policy()}, {"client": "x" * 32})) as client:
        response = post_preview(client, "[[PD:forged]]", policy())
    assert response.status_code == 422
    assert response.json() == {"detail": "reserved_token_syntax"}


def test_preview_does_not_change_process_contract_or_an_existing_pair():
    current = policy(mode_by_type={"EMAIL": "redact"})
    source = "PIN 1234; private@example.org"
    with TestClient(create_app({"client": current}, {"client": "x" * 32})) as client:
        body = {"payload_id": "before-preview", "payload": source}
        masked_response = client.post("/process", json=body)
        assert masked_response.status_code == 200
        masked = masked_response.json()["result"]
        assert "1234" not in masked and "private@example.org" not in masked
        preview = post_preview(client, source, Policy(version="unsafe-draft", detect_types=set()))
        assert preview.status_code == 200
        restored = client.post("/process", json={**body, "payload": masked})
        assert restored.status_code == 200
        assert restored.json() == {"result": source}
