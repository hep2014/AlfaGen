import pytest

from alpha_privacy.core import BaselineDetector, Gateway, MemoryVault, Policy
from alpha_privacy.evaluate import evaluate
from alpha_privacy.synthetic import LABELS, generate, record, validate


@pytest.mark.parametrize("text,kind,value", [
    ("Клиент Александр Пушкин; просит ответить.", "PERSON", "Александр Пушкин"),
    ("ФИО: Иван Фантазиев.", "PERSON", "Иван Фантазиев"),
    ("фио: фантазиев иван сергеевич.", "PERSON", "фантазиев иван сергеевич"),
    ("ФИО: Александр Сергеевич Фантазиев.", "PERSON", "Александр Сергеевич Фантазиев"),
    ("ФИО: Анна Образцова-Тестова.", "PERSON", "Анна Образцова-Тестова"),
    ("Дата рождения: 1990-03-21.", "BIRTH_DATE", "1990-03-21"),
    ("Родилась 21 марта 1990 года.", "BIRTH_DATE", "21 марта 1990"),
    ("Дата рождения: 03.21.1990.", "BIRTH_DATE", "03.21.1990"),
    ("Паспорт выдан 2020/21/03.", "ISSUE_DATE", "2020/21/03"),
    ("Дата выдачи паспорта — 21.03.2020.", "ISSUE_DATE", "21.03.2020"),
    ("Адрес клиента: г. Тестоград, ул. Вымышленная, д. 8, кв. 12.", "ADDRESS", "г. Тестоград, ул. Вымышленная, д. 8, кв. 12"),
    ("Адрес регистрации: Россия, 000000, г. Тестоград, пер. Учебный, д. 2а/3.", "ADDRESS", "Россия, 000000, г. Тестоград, пер. Учебный, д. 2а/3"),
])
def test_spans_and_exact_restoration(text, kind, value):
    detector = BaselineDetector()
    spans = detector.detect(text, detector.supported_types)
    expected = (["Тестоград", "Вымышленная", "8", "12"] if "Вымышленная" in value
                else ["Россия, 000000", "Тестоград", "Учебный", "2а/3"] if "Учебный" in value
                else [value])
    assert [(s.kind, text[s.start:s.end]) for s in spans] == [(kind, part) for part in expected]
    gateway = Gateway(detector, MemoryVault())
    masked = gateway.mask("test", text, Policy(version="test", detect_types=detector.supported_types))
    assert value not in masked["text"]
    assert gateway.restore("test", masked["session_id"], masked["text"]) == text


@pytest.mark.parametrize("text", [
    "Поэт Александр Пушкин написал стихотворение.",
    "Адрес отделения банка: г. Тестоград, ул. Вымышленная, д. 1.",
    "Адрес офиса: г. Тестоград, ул. Вымышленная, д. 1.",
    "Дата встречи: 21.03.2020.", "Клиент просит помощь.",
])
def test_context_negatives(text):
    assert BaselineDetector().detect(text, BaselineDetector.supported_types) == []


def test_public_name_does_not_whitelist_namesake():
    text = "Поэт Александр Пушкин. Клиент Александр Пушкин; дата рождения: 06.06.1990."
    spans = BaselineDetector().detect(text, BaselineDetector.supported_types)
    assert [s.kind for s in spans] == ["PERSON", "BIRTH_DATE"]
    assert spans[0].start == text.rindex("Александр")


def test_synthetic_reproducibility_coverage_offsets():
    rows = generate()
    assert rows == generate()
    assert rows != generate(seed=1)
    validate(rows)
    for split in ["train", "dev", "test"]:
        assert {e["type"] for r in rows if r["split"] == split for e in r["entities"]} == set(LABELS)


def test_evaluator_counts_unsupported_categories_and_negatives():
    rows = [record("one", "test", "unit", ["Email: ", ("EMAIL", "test@example.org")]),
            record("two", "test", "unit", ["Место рождения: ", ("BIRTH_PLACE", "Тестоград")]),
            record("three", "test", "unit", ["Email: false-positive@example.org"])]
    result = evaluate(rows, BaselineDetector.supported_types - {"BIRTH_PLACE"})
    assert result["micro"]["tp"] == 1
    assert result["micro"]["fp"] == 1
    assert result["micro"]["fn"] == 1
    assert result["roundtrip_exact"] == 3  # roundtrip alone does not prove protection
    assert result["examples_with_uncovered_sensitive_characters"] == 1


def test_invalid_annotations_rejected():
    row = record("x", "train", "unit", [("PERSON", "Иван Фантазиев")])
    row["entities"][0]["start"] = 1
    with pytest.raises(ValueError):
        validate([row])
