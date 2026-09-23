r"""Challenge-тесты: детектор потенциальных багов.

Стратегия: собрать максимум потенциально проблемных кейсов,
прогнать, увидеть полную картину, потом чинить всё разом.

НЕ ломают существующие тесты. Запуск:
    .\.venv\Scripts\python -m pytest tests/test_challenge.py -v

Категории:
- CARDHOLDER (латиница заглавными, кириллица).
- PERSON (разные имена, падежи, омонимы).
- ADDRESS (компоненты, разные форматы).
- BIRTH_PLACE, CITIZENSHIP, PASSPORT_ISSUER.
- Даты текстом, падежи месяцев.
- Обфускации (пробелы, точки).
- Смешанные предложения.
"""
import pytest

from alpha_privacy.core import BaselineDetector, Gateway, MemoryVault, Policy

ALL_TYPES = BaselineDetector.supported_types


def _run(text: str):
    """Прогнать текст через сервис: (masked, detected_types, restored)."""
    detector = BaselineDetector()
    gateway = Gateway(detector, MemoryVault())
    policy = Policy(version="challenge", detect_types=ALL_TYPES)
    masked = gateway.mask("challenge", text, policy)
    restored = gateway.restore("challenge", masked["session_id"], masked["text"])
    return masked["text"], masked["detected_types"], restored


# ============================================================================
# 1. CARDHOLDER — держатель карты
# ============================================================================

@pytest.mark.parametrize("text", [
    "Имя держателя: IVAN IVANOV, карта 4111 1111 1111 1111.",
    "Имя держателя: ivan ivanov, карта 4111 1111 1111 1111.",
    "Имя держателя: Ivan Ivanov, карта 4111 1111 1111 1111.",
    "Имя держателя: ИВАНОВ ИВАН, карта 4111 1111 1111 1111.",
    "Имя держателя: Иванов Иван, карта 4111 1111 1111 1111.",
    "Имя держателя карты: PETR PETROV, карта 4111 1111 1111 1111.",
    "Cardholder: IVAN IVANOV, card 4111 1111 1111 1111.",
])
def test_cardholder_formats(text):
    _masked, detected, restored = _run(text)
    assert "CARDHOLDER" in detected, f"CARDHOLDER не найден: {detected} в '{text}'"
    assert restored == text


# ============================================================================
# 2. PERSON — разные имена, падежи
# ============================================================================

@pytest.mark.parametrize("text,expected_count", [
    ("Клиент Иванов Иван, email ivanov@example.org. Клиент Петров Пётр, email petrov@example.org.", 2),
    ("Клиент Иванов Иван и клиент Петров Пётр.", 2),
    ("Клиент Сидоров Николай, клиент Кузнецова Екатерина.", 2),
    ("Клиент Смирнов Алексей, клиент Волкова Татьяна.", 2),
    ("Клиент Морозов Андрей, клиент Новикова Юлия.", 2),
])
def test_person_multiple(text, expected_count):
    _masked, detected, restored = _run(text)
    assert detected.get("PERSON") == expected_count, \
        f"Ожидалось {expected_count} PERSON, найдено {detected.get('PERSON')}: {detected} в '{text}'"
    assert restored == text


@pytest.mark.parametrize("text", [
    "Клиент Иванов Иван Иванович.",
    "Клиента Иванова Ивана Ивановича просим.",         # падеж
    "Клиенту Иванову Ивану Ивановичу.",                 # падеж
    "ФИО: Петров Пётр Петрович.",
    "ФИО: Сидорова Анна Сергеевна.",
])
def test_person_cases(text):
    _masked, detected, restored = _run(text)
    assert "PERSON" in detected, f"PERSON не найден: {detected} в '{text}'"
    assert restored == text


# ============================================================================
# 3. ADDRESS — компоненты, разные форматы
# ============================================================================

@pytest.mark.parametrize("text", [
    "Адрес: г. Москва, ул. Ленина, д. 5, кв. 10.",
    "Адрес регистрации: Россия, 123456, г. Москва, ул. Ленина, д. 5.",
    "Адрес проживания: г. Санкт-Петербург, пр. Невский, д. 1.",
    "Проживает по адресу: г. Москва, пер. Учебный, д. 2а/3.",
    "Адрес клиента: г. Москва, ул. Ленина, д. 5, кв. 10.",
    "Адрес доставки: г. Москва, ул. Ленина, д. 5.",
])
def test_address_components(text):
    _masked, detected, restored = _run(text)
    assert "ADDRESS" in detected, f"ADDRESS не найден: {detected} в '{text}'"
    assert restored == text


# ============================================================================
# 4. BIRTH_PLACE, CITIZENSHIP, PASSPORT_ISSUER
# ============================================================================

@pytest.mark.parametrize("text,kind", [
    ("Место рождения: г. Москва.", "BIRTH_PLACE"),
    ("Место рождения: город Тестоград.", "BIRTH_PLACE"),
    ("Место рождения: Москва.", "BIRTH_PLACE"),
    ("Гражданство: Российская Федерация.", "CITIZENSHIP"),
    ("Гражданство: РФ.", "CITIZENSHIP"),
    ("Гражданство: Россия.", "CITIZENSHIP"),
    ("Орган, выдавший паспорт: Учебный отдел № 1.", "PASSPORT_ISSUER"),
    ("Орган выдачи паспорта: ОВД г. Москвы.", "PASSPORT_ISSUER"),
    ("Паспорт выдан: ОВД г. Москвы.", "PASSPORT_ISSUER"),
])
def test_rare_types(text, kind):
    _masked, detected, restored = _run(text)
    assert kind in detected, f"{kind} не найден: {detected} в '{text}'"
    assert restored == text


# ============================================================================
# 5. Даты текстом, падежи
# ============================================================================

@pytest.mark.parametrize("text", [
    "Родилась 21 марта 1990 года.",
    "Родился 3 апреля 1985 года.",
    "Дата рождения: двадцать первое марта 1990 года.",
    "Дата рождения: 1 января 2000 года.",
    "Дата выдачи паспорта: 5 мая 2020 года.",
])
def test_dates_text(text):
    _masked, detected, restored = _run(text)
    has_date = "BIRTH_DATE" in detected or "ISSUE_DATE" in detected
    assert has_date, f"Дата не найдена: {detected} в '{text}'"
    assert restored == text


# ============================================================================
# 6. Обфускации
# ============================================================================

@pytest.mark.parametrize("text", [
    "Email: test @ example.org",
    "Телефон: +7 999 123 45 67",
    "ИНН: 1234 5678 9012",
    "Паспорт: 45 09 123 456",
])
def test_obfuscations(text):
    _masked, detected, restored = _run(text)
    has_any = any(k in detected for k in ["EMAIL", "PHONE", "INN", "PASSPORT_RU"])
    assert has_any, f"Ничего не найдено: {detected} в '{text}'"
    assert restored == text


# ============================================================================
# 7. Смешанные предложения — все типы
# ============================================================================

def test_all_types_in_one():
    text = ("Клиент Иванов Иван Иванович, паспорт серия 45 09 номер 123456, "
            "выдан ОВД г. Москвы 21.03.2010, код подразделения 123-456, "
            "дата рождения 21.03.1990, место рождения г. Москва, "
            "гражданство РФ, адрес: г. Москва, ул. Ленина, д. 5, кв. 10, "
            "email test@example.org, телефон +7 (999) 123-45-67, "
            "ИНН 123456789012, карта 4111 1111 1111 1111, CVV 123, "
            "пин-код 1234, имя держателя IVAN IVANOV.")
    _masked, detected, restored = _run(text)
    expected = {"PERSON", "PASSPORT_RU", "PASSPORT_ISSUER", "ISSUE_DATE",
                "DEPARTMENT_CODE", "BIRTH_DATE", "BIRTH_PLACE", "CITIZENSHIP",
                "ADDRESS", "EMAIL", "PHONE", "INN", "CARD", "CVV", "PIN",
                "CARDHOLDER"}
    missing = expected - set(detected.keys())
    assert not missing, f"Не найдены типы: {missing}. Найдено: {detected}"
    assert restored == text


# ============================================================================
# 8. Второе вхождение — два одинаковых типа
# ============================================================================

def test_two_emails():
    text = "Пишите на test@example.org или на test2@example.org."
    _masked, detected, restored = _run(text)
    assert detected.get("EMAIL") == 2, f"Ожидалось 2 EMAIL: {detected}"
    assert restored == text


def test_two_phones():
    text = "Звоните +7 (999) 111-11-11 или +7 (999) 222-22-22."
    _masked, detected, restored = _run(text)
    assert detected.get("PHONE") == 2, f"Ожидалось 2 PHONE: {detected}"
    assert restored == text


def test_two_passports():
    text = "Паспорт 4509 123456 и паспорт 4509 654321."
    _masked, detected, restored = _run(text)
    assert detected.get("PASSPORT_RU") == 2, f"Ожидалось 2 PASSPORT: {detected}"
    assert restored == text



# ============================================================================
# 9. ДАТЫ ПРОПИСЬЮ — числительные словами
# ============================================================================

@pytest.mark.parametrize("text", [
    # Простые числительные
    "Дата рождения: первое января 2000 года.",
    "Дата рождения: второе февраля 1985 года.",
    "Дата рождения: третье марта 1990 года.",
    "Дата рождения: пятое мая 1975 года.",
    "Дата рождения: десятое июня 1980 года.",
    # Составные числительные
    "Дата рождения: двадцатое июля 1992 года.",
    "Дата рождения: двадцать первое марта 1990 года.",
    "Дата рождения: двадцать второе апреля 1988 года.",
    "Дата рождения: двадцать третье мая 1991 года.",
    "Дата рождения: тридцатое июня 1983 года.",
    "Дата рождения: тридцать первое декабря 1999 года.",
    # Без слова «года»
    "Дата рождения: двадцать первое марта 1990.",
    "Дата рождения: первое января 2000.",
    # С контекстом «родился/родилась»
    "Родился двадцать первое марта 1990 года.",
    "Родилась третье апреля 1985 года.",
    # Выдача паспорта
    "Дата выдачи паспорта: двадцать первое марта 2010 года.",
    "Паспорт выдан пятое мая 2015 года.",
])
def test_dates_words(text):
    _masked, detected, restored = _run(text)
    has_date = "BIRTH_DATE" in detected or "ISSUE_DATE" in detected
    assert has_date, f"Дата прописью не найдена: {detected} в '{text}'"
    assert restored == text, f"Roundtrip сломан: '{restored}' != '{text}'"


@pytest.mark.parametrize("text", [
    # Ловушки — НЕ должны маскироваться
    "Первое впечатление было хорошим.",
    "Второе место занял Иванов.",
    "Третье января — это дата.",
    "Двадцать первое место в рейтинге.",
])
def test_dates_words_traps(text):
    _masked, detected, _restored = _run(text)
    # Если это не дата с контекстом рождения/выдачи — не маскируем
    # (кроме случая, когда слово «января» — месяц, но без года)
    if "рождения" not in text.lower() and "выдачи" not in text.lower() and "выдан" not in text.lower():
        assert "BIRTH_DATE" not in detected, f"Ложное BIRTH_DATE: {detected}"
        assert "ISSUE_DATE" not in detected, f"Ложное ISSUE_DATE: {detected}"