from unittest.mock import patch

import pytest

from alpha_privacy.core import BaselineDetector
from alpha_privacy.field_rules import FieldRule
from alpha_privacy.gates import fold_for_search
from alpha_privacy.robustness import generate_robustness


def assert_full_scan_equivalence(text, detector=None):
    detector = detector or BaselineDetector()
    kinds = detector.supported_types
    fast = detector.detect(text, kinds)
    with patch("alpha_privacy.core.fold_for_search", return_value=None):
        full = detector.detect(text, kinds)
    assert fast == full
    for kind in {span.kind for span in full}:
        with patch("alpha_privacy.core.fold_for_search", return_value=None):
            expected = detector.detect(text, {kind})
        assert detector.detect(text, {kind}) == expected
    assert detector.detect(text, set()) == []
    return full


@pytest.mark.parametrize("row", generate_robustness(), ids=lambda row: row["id"])
@pytest.mark.parametrize("case_form", [str.lower, str.upper, str.swapcase])
@pytest.mark.parametrize("position", ["start", "end"])
def test_long_corpus_matches_full_regex_scan(row, case_form, position):
    text = case_form(row["text"])
    padding = "пояснение " * 550
    text = text + "\n" + padding if position == "start" else padding + "\n" + text
    assert_full_scan_equivalence(text)


@pytest.mark.parametrize("separator", ["\t", "\r\n", "\u00a0", "   "])
def test_split_field_labels_remain_eligible(separator):
    text = ("Дата рождения: 21.03.1990; место рождения: Москва; "
            "имя держателя: IVAN IVANOV; код подразделения: 770-001; "
            "свяжитесь с Ивановым Иваном; выдан ОВД Москвы 21.03.2010.")
    for label in ("Дата рождения", "место рождения", "имя держателя", "код подразделения",
                  "свяжитесь с", "выдан ОВД"):
        text = text.replace(label, label.replace(" ", separator))
    text = "пояснение " * 550 + "\n" + text
    kinds = {s.kind for s in assert_full_scan_equivalence(text)}
    assert {"BIRTH_DATE", "BIRTH_PLACE", "CARDHOLDER", "DEPARTMENT_CODE", "PERSON",
            "PASSPORT_ISSUER", "ISSUE_DATE"} <= kinds


@pytest.mark.parametrize("text,kind", [
    ("Иванов Иван Иванович", "PERSON"), ("4111 1111 1111 1111", "CARD"),
    ("7707083893", "INN"), ("ПАᲃПОРТ 45 09 123456", "PASSPORT_RU"),
    ("ᲀыдан ОВД Москвы 21.03.2010", "PASSPORT_ISSUER"), ("Гᲂрод: Москва", "ADDRESS"),
    ("PİN 1234", "PIN"), ("PıN 1234", "PIN"), ("Ф.И.О. Иванов Иван Иванович", "PERSON"),
    ("д.р. 21.03.1990", "BIRTH_DATE"), ("др 21.03.1990", "BIRTH_DATE"),
    ("заёмщик Иванов Иван", "PERSON"), ("заемщик Иванов Иван", "PERSON"),
    ("+44 20 7946 0958", "PHONE"),
])
def test_bare_values_special_casing_and_label_aliases(text, kind):
    spans = assert_full_scan_equivalence(" " * 4100 + text + " " * 4100)
    assert kind in {span.kind for span in spans}


@pytest.mark.parametrize("length", [4095, 4096, 4097, 100_001])
def test_gate_threshold_and_original_offsets(length):
    text = " " * (length - len("a@example.org")) + "a@example.org"
    assert (fold_for_search(text) is None) is (length <= 4096)
    spans = assert_full_scan_equivalence(text)
    assert [(span.start, span.end) for span in spans] == [(length - len("a@example.org"), length)]


def test_unhinted_custom_rules_and_kelvin_case_equivalence():
    detector = BaselineDetector([FieldRule(kind="INTERNAL_ID", labels=["Key"])])
    text = "пояснение " * 550 + "\nKey: A-123"
    assert [span.kind for span in assert_full_scan_equivalence(text, detector)] == ["INTERNAL_ID"]
