import pytest

from alpha_privacy.core import BaselineDetector, Gateway, MemoryVault, Policy
from alpha_privacy.robustness import generate_robustness

CASE_FORMS = [pytest.param(lambda text: text, id="original"),
              pytest.param(str.lower, id="lower"), pytest.param(str.upper, id="upper"),
              pytest.param(str.swapcase, id="swapcase")]


@pytest.mark.parametrize("case_form", CASE_FORMS)
@pytest.mark.parametrize("text,values", [
    ("Банк запросил анкету, город клиента: Москва.", ["Москва"]),
    ("Банк запросил анкету, город: Москва.", ["Москва"]),
    ("Адрес офиса известен. Город: Москва.", ["Москва"]),
    ("Адрес офиса: город клиента: Москва, дом: 12.", ["Москва", "12"]),
    ("Данные офиса:\nДанные клиента:\nгород: Москва, квартира: 42.", ["Москва", "42"]),
    ("Город: Москва. Квартира: 42.", ["Москва", "42"]),
    ("Город: Нижний Новгород страна: Россия дом: 12а/3", ["Нижний Новгород", "Россия", "12а/3"]),
    ("Город: Москва находится на карте.", ["Москва"]),
    ("Улица: Большая Тестовая расположена рядом.", ["Большая Тестовая"]),
    ("Город: Москва комментарий: доставить завтра.", ["Москва"]),
    ("Город: нижний новгород, улица: большая тестовая.", ["нижний новгород", "большая тестовая"]),
    ("Город: Нижний новгород, улица: Красного знамени.", ["Нижний новгород", "Красного знамени"]),
    ("Улица: Находкинская.", ["Находкинская"]),
    ("Город:\nКвартира: 42.", ["42"]),
    ("Город: Ростов-на-Дону; страна: Российская Федерация.", ["Ростов-на-Дону", "Российская Федерация"]),
])
def test_address_values_do_not_swallow_neighbours_or_inherit_unrelated_public_words(text, values, case_form):
    text = case_form(text)
    values = [case_form(value) for value in values]
    detector = BaselineDetector()
    spans = detector.detect(text, {"ADDRESS"})
    assert [(span.start, span.end, span.kind) for span in spans] == [
        (text.index(value), text.index(value) + len(value), "ADDRESS") for value in values
    ]
    gateway = Gateway(detector, MemoryVault())
    result = gateway.mask("client", text, Policy(version="precision", detect_types={"ADDRESS"}))
    assert gateway.restore("client", result["session_id"], result["text"]) == text


@pytest.mark.parametrize("case_form", CASE_FORMS)
@pytest.mark.parametrize("text", [
    "Адрес отделения банка: Город: Москва.",
    "Данные офиса, улица: Ленина.",
    "Адрес офиса:\nгород: Москва, улица: Ленина, дом: 5.",
    "Офис: город: Москва, дом: 5.",
    "Данные клиента:\nДанные офиса:\nгород: Москва.",
    "Город: неизвестно, квартира: не указана.",
    "Город:\nНеобязательное поле",
    "Город: Москва1.",
    "Город: Москва_code.",
])
def test_public_address_blocks_and_empty_fields_are_not_personal(text, case_form):
    assert BaselineDetector().detect(case_form(text), {"ADDRESS"}) == []


@pytest.mark.parametrize("case_form", CASE_FORMS)
def test_public_scope_stops_at_paragraph_boundary(case_form):
    text = case_form("Данные офиса:\nгород: Тверь\n\nгород: Москва")
    spans = BaselineDetector().detect(text, {"ADDRESS"})
    assert [(span.start, span.end) for span in spans] == [(text.index(case_form("Москва")), len(text))]


@pytest.mark.parametrize("case_form", CASE_FORMS[1:])
@pytest.mark.parametrize("row", generate_robustness(), ids=lambda row: row["id"])
def test_all_labelled_variants_and_negatives_are_case_invariant(row, case_form):
    text = case_form(row["text"])
    detector = BaselineDetector()
    spans = detector.detect(text, detector.supported_types)
    assert [(span.start, span.end, span.kind) for span in spans] == [
        (entity["start"], entity["end"], entity["type"]) for entity in row["entities"]
    ]
