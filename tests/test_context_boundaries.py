import pytest

from alpha_privacy.core import BaselineDetector, Gateway, MemoryVault, Policy

CASE_FORMS = [pytest.param(lambda text: text, id="original"),
              pytest.param(str.lower, id="lower"), pytest.param(str.upper, id="upper"),
              pytest.param(str.swapcase, id="swapcase")]


@pytest.mark.parametrize("case_form", CASE_FORMS)
@pytest.mark.parametrize("text,kind,values", [
    ("Клиент Иван приехал вчера.", "PERSON", ["Иван"]),
    ("Клиент Анна приехала вчера.", "PERSON", ["Анна"]),
    ("Клиент Иван Приехалов.", "PERSON", ["Иван Приехалов"]),
    ("ФИО: Анна Образцова-Тестова.", "PERSON", ["Анна Образцова-Тестова"]),
    ("ФИО: Александр Сергеевич Фантазиев.", "PERSON", ["Александр Сергеевич Фантазиев"]),
    ("Клиент Иван паспорт: 4509 123456.", "PERSON", ["Иван"]),
    ("Клиент Иван дата рождения: 21.03.1990.", "PERSON", ["Иван"]),
    ("ФИО: Иван Фантазиев телефон: +7 999 123-45-67.", "PERSON", ["Иван Фантазиев"]),
    ("Место рождения: Москва сейчас живёт в Казани.", "BIRTH_PLACE", ["Москва"]),
    ("Место рождения: Москва сейчас живет в Казани.", "BIRTH_PLACE", ["Москва"]),
    ("Место рождения: Нижний новгород сейчас живёт в Казани.", "BIRTH_PLACE", ["Нижний новгород"]),
    ("Место рождения: Нижний Новгород гражданство: РФ.", "BIRTH_PLACE", ["Нижний Новгород"]),
    ("Место рождения: поселок имени Ленина.", "BIRTH_PLACE", ["поселок имени Ленина"]),
    ("Место рождения: Санкт-Петербург.", "BIRTH_PLACE", ["Санкт-Петербург"]),
    ("Имя держателя: IVAN IVANOV please call tomorrow.", "CARDHOLDER", ["IVAN IVANOV"]),
    ("Имя держателя: IVAN SERGEEVICH IVANOV please call tomorrow.", "CARDHOLDER", ["IVAN SERGEEVICH IVANOV"]),
    ("Имя держателя: JEAN-PAUL DE LA FONTAINE.", "CARDHOLDER", ["JEAN-PAUL DE LA FONTAINE"]),
    ("Имя держателя: CALL IVANOV.", "CARDHOLDER", ["CALL IVANOV"]),
    ("Имя держателя: IVAN IVANOV cvv: 123.", "CARDHOLDER", ["IVAN IVANOV"]),
    ("Cardholder: IVAN IVANOV дата рождения = 21.03.1990.", "CARDHOLDER", ["IVAN IVANOV"]),
])
def test_narrative_and_next_fields_preserve_precise_values(text, kind, values, case_form):
    text = case_form(text)
    values = [case_form(value) for value in values]
    detector = BaselineDetector()
    spans = detector.detect(text, {kind})
    assert [(span.start, span.end, span.kind) for span in spans] == [
        (text.index(value), text.index(value) + len(value), kind) for value in values
    ]
    gateway = Gateway(detector, MemoryVault())
    result = gateway.mask("client", text, Policy(version="boundaries", detect_types={kind}))
    assert gateway.restore("client", result["session_id"], result["text"]) == text


@pytest.mark.parametrize("case_form", CASE_FORMS)
@pytest.mark.parametrize("text", [
    "Клиент приехал вчера.",
    "Место рождения: не указано гражданство: РФ.",
    "Имя держателя: not provided cvv: 123.",
    "На карте указано место рождения, но значение отсутствует.",
])
def test_empty_or_placeholder_context_does_not_create_values(text, case_form):
    assert BaselineDetector().detect(case_form(text), {"PERSON", "BIRTH_PLACE", "CARDHOLDER"}) == []
