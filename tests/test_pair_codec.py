import hashlib
import json
import random

import pytest

from alpha_privacy.core import (
    BaselineDetector,
    Gateway,
    MemoryVault,
    Policy,
    ProcessingError,
    VaultError,
)
from alpha_privacy.pair_codec import pack_pair, replay_pair
from alpha_privacy.process import PayloadConflict, ProcessService

ALL = BaselineDetector.supported_types


def service(vault=None, policy=None):
    return ProcessService(Gateway(BaselineDetector(), MemoryVault()),
                          policy or Policy(version="test", detect_types=ALL), vault or MemoryVault())


def stored(instance, identifier):
    return instance.vault.get("evaluator", hashlib.sha256(identifier.encode()).hexdigest())


@pytest.mark.parametrize("suffix", [
    "ИНН 7707083893; номер заказа 7707083893.",
    "PIN 1234; CVV 1234; число 1234.",
    "a@example.org; a@example.org; клиент Иванов Иван.",
    "Загранпаспорт: 72 1234567; паспорт серия 45 09 номер 123456.",
    "Просто обычный текст.",
])
def test_sparse_unicode_pairs_store_only_replacements_and_replay_exactly(suffix):
    instance = service()
    public = "🧪 е\u0308 ё\r\nОбычное описание без реквизитов. " * 500
    original = public + suffix
    masked, _ = instance.process("same", original)
    record = stored(instance, "same")
    assert record["format"] == "patch-v1"
    assert "Обычное описание" not in json.dumps(record, ensure_ascii=False)
    assert instance.vault.used_bytes < 4096
    for _ in range(3):
        assert instance.process("same", original)[0] == masked
        assert instance.process("same", masked)[0] == original
    # A new service using the same vault can still read the authenticated record.
    assert service(instance.vault).process("same", masked)[0] == original


def test_repeated_value_outside_sensitive_field_is_not_replaced_on_retry():
    instance = service()
    original = "описание " * 700 + "ИНН 7707083893; номер заказа 7707083893."
    masked, _ = instance.process("one", original)
    assert "номер заказа 7707083893" in masked
    assert masked.count("7707083893") == 1
    assert instance.process("one", original)[0] == masked
    assert instance.process("one", masked)[0] == original


def test_sparse_capacity_depends_on_secrets_not_the_large_public_text():
    instance = service(MemoryVault(capacity=100, max_bytes=64_000))
    for index in range(32):
        original = "Обычное описание. " * 5000 + f"{index}@example.org"
        masked, _ = instance.process(str(index), original)
        assert instance.process(str(index), masked)[0] == original
    assert len(instance.vault.entries) == 32
    assert instance.vault.used_bytes < 64_000


def test_large_dense_repeated_values_fit_compact_plan_and_restore():
    instance = service()
    original = "a@b.ru " * 22_000
    masked, _ = instance.process("dense", original)
    assert len(masked) > 1_000_000
    assert stored(instance, "dense")["format"] == "patch-v1"
    assert instance.vault.used_bytes < 512_000
    assert instance.process("dense", original)[0] == masked
    assert instance.process("dense", masked)[0] == original


def test_huge_secret_short_mask_uses_smaller_full_pair_and_worker_lane():
    instance = service()
    original = "a" * 40_000 + "@example.org"
    masked, _ = instance.process("huge-value", original)
    assert len(masked) < 128
    assert "original" in stored(instance, "huge-value")
    assert not instance.can_inline("huge-value", masked)
    with pytest.raises(VaultError, match="process_busy"):
        instance.process("huge-value", masked, blocking=False)
    assert instance.process("huge-value", masked)[0] == original


def test_small_conflict_with_large_public_only_pair_is_safe_inline():
    instance = service()
    instance.process("public", "слово " * 10_000)
    assert instance.can_inline("public", "conflict")
    with pytest.raises(PayloadConflict):
        instance.process("public", "conflict", blocking=False)


def test_direct_irreversible_policy_falls_back_to_reversible_full_pair():
    instance = service(policy=Policy(version="test", detect_types=ALL, mode_by_type={"PIN": "redact"}))
    original = "слово " * 1000 + "PIN 1234"
    masked, _ = instance.process("one", original)
    assert masked.endswith("PIN [REDACTED:PIN]")
    assert "original" in stored(instance, "one")
    assert instance.process("one", masked)[0] == original


def test_compact_tags_bind_the_entire_text_and_payload_id():
    instance = service()
    original = "слово " * 1000 + "a@example.org"
    masked, _ = instance.process("one", original)
    for wrong in (original + " ", masked + " ", "changed " + masked, masked.replace("EMAIL", "PHONE")):
        with pytest.raises(PayloadConflict):
            instance.process("one", wrong)
    with pytest.raises(ProcessingError, match="reserved_token_syntax"):
        instance.process("other", masked)
    copied = stored(instance, "one")
    other_key = hashlib.sha256(b"other").hexdigest()
    instance.vault.put("evaluator", copied, 300, session=other_key)
    with pytest.raises(PayloadConflict):
        instance.process("other", masked)
    assert instance.process("one", masked)[0] == original


def test_compact_no_pii_completion_ttl_and_expiry(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("alpha_privacy.core.time.monotonic", lambda: now[0])
    instance = service(MemoryVault(capacity=1))
    text = "слово " * 1000
    assert instance.process("one", text)[0] == text
    now[0] = 10
    assert instance.process("one", text)[0] == text
    now[0] = 69
    assert instance.process("one", text)[0] == text
    now[0] = 70
    instance.process("two", text)
    assert len(instance.vault.entries) == 1


def test_failed_compact_write_does_not_reserve_id():
    instance = service(MemoryVault(max_bytes=1))
    original = "слово " * 1000 + "a@example.org"
    with pytest.raises(VaultError, match="vault_unavailable"):
        instance.process("retry", original)
    assert not instance.vault.entries
    instance.vault.max_bytes = 4096
    masked, _ = instance.process("retry", original)
    assert instance.process("retry", masked)[0] == original


@pytest.mark.parametrize("seed", range(20))
def test_gap_plan_replays_random_unicode_boundaries_without_global_replacement(seed):
    rng = random.Random(seed)
    values = ["1234", "ё\u0308", "🧪", "a@example.org"]
    mapping = {f"[[PD:{'a' * 32}:TEST:{i}]]": value for i, value in enumerate(values)}
    original, masked = ["обычный текст " * 1000], ["обычный текст " * 1000]
    for _ in range(40):
        # Some public gaps contain values identical to protected ones.
        gap = rng.choice(["", "\r\n", "😀: ", "1234", "e\u0301"])
        token = rng.choice(list(mapping))
        original.extend((gap, mapping[token]))
        masked.extend((gap, token))
    original, masked = "".join(original), "".join(masked)
    record = json.loads(pack_pair(original, masked, mapping, "synthetic-id"))
    assert record["format"] == "patch-v1"
    assert replay_pair(record, original, "synthetic-id") == (masked, False)
    assert replay_pair(record, masked, "synthetic-id") == (original, True)
    assert replay_pair(record, masked, "other-id") is None
