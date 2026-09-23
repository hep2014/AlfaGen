import pytest

from alpha_privacy.core import BaselineDetector


@pytest.mark.parametrize("text,kind,values", [
    ("Иванов Иван Иванович", "PERSON", ["Иванов Иван Иванович"]),
    ("Иван Иванович Иванов", "PERSON", ["Иван Иванович Иванов"]),
    ("Клиента Иванова Ивана Ивановича просим.", "PERSON", ["Иванова Ивана Ивановича"]),
    ("Клиенту Иванову Ивану Ивановичу.", "PERSON", ["Иванову Ивану Ивановичу"]),
    ("Паспорт: серия 45 09 номер 123456.", "PASSPORT_RU", ["45 09", "123456"]),
    ("Адрес: г. Москва, ул. Ленина, д. 5, кв. 10.", "ADDRESS", ["Москва", "Ленина", "5", "10"]),
    ("Место рождения: г. Москва, гражданство РФ.", "BIRTH_PLACE", ["Москва"]),
    ("Родилась 21 марта 1990 года.", "BIRTH_DATE", ["21 марта 1990"]),
    ("Паспорт выдан пятое мая 2015 года.", "ISSUE_DATE", ["пятое мая 2015"]),
    ("Орган выдачи паспорта: ОВД г. Москвы.", "PASSPORT_ISSUER", ["ОВД г. Москвы"]),
])
def test_exact_sensitive_boundaries(text, kind, values):
    spans = BaselineDetector().detect(text, BaselineDetector.supported_types)
    assert [(s.kind, text[s.start:s.end]) for s in spans] == (
        [(kind, value) for value in values] + ([('CITIZENSHIP', 'РФ')] if "гражданство" in text else [])
    )


@pytest.mark.parametrize("text", [
    "Клиент Иван просит помощь.", "Клиент Роман получил ответ.",
    "Клиент нов продукт.", "Клиент волк серый.",
    "Дата встречи: первое января 2000 года.", "Релиз выдан 21.03.2020.",
    "cvv2123", "pin1234", "ИННовация 1234567890", "Номер заказа 4111111111111111",
    "Адрес офиса: г. Москва, ул. Ленина, д. 5.",
    "Место рождения: не указано.", "Гражданство: не указано.",
    "Гражданство обязательно.", "Имя держателя: not provided.",
    "Орган выдачи паспорта: отсутствует.",
])
def test_negative_contexts(text):
    assert BaselineDetector().detect(text, BaselineDetector.supported_types) == []


@pytest.mark.parametrize("prefix", ["ИНН", "ФИО", "Паспорт", "Карта", "Дата рождения"])
def test_long_whitespace_near_misses(prefix):
    assert BaselineDetector().detect(prefix + " " * 100_000 + "!", BaselineDetector.supported_types) == []


def test_issuer_date_and_following_field_are_separate():
    text = "Паспорт выдан ОВД г. Москвы 21.03.2010, код подразделения 123-456."
    spans = BaselineDetector().detect(text, BaselineDetector.supported_types)
    assert [(s.kind, text[s.start:s.end]) for s in spans] == [
        ("PASSPORT_ISSUER", "ОВД г. Москвы"), ("ISSUE_DATE", "21.03.2010"),
        ("DEPARTMENT_CODE", "123-456"),
    ]
