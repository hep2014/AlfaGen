"""Additional bounded, contextual rules and checksum-backed bare identifiers."""
import re

from .context import FIELD_PLACEHOLDER
from .gates import may_contain, possible_patterns

EXTRA_TYPES = {"FOREIGN_PASSPORT", "BIRTH_CERTIFICATE"}
PATTERNS = {
    "FOREIGN_PASSPORT": re.compile(r"\bзагранпаспорт(?:а)?\s*+[:№-]?\s*+(?P<value>\d{2}[ -]?\d{7})(?!\d)", re.IGNORECASE),
    "BIRTH_CERTIFICATE": re.compile(r"\bсвидетельство\s+о\s+рождении\s*+[:№-]?\s*+(?P<value>[IVXLCDMІХ]{1,8}[ -]?[А-ЯЁ]{2}\s+\d{6})(?!\w)", re.IGNORECASE),
    "DRIVER_LICENSE": re.compile(r"\b(?:водительское\s+удостоверение|в/у)\s*+[:№-]?\s*+(?P<value>\d{2}\s*[А-ЯЁ]{2}\s*\d{6})(?!\w)", re.IGNORECASE),
    "PHONE": re.compile(r"(?<![\w+])(?P<value>\+[1-9](?:[ ()-]{0,3}\d){9,14})(?![\w]|[ ()-]?\d)", re.IGNORECASE),
    "ADDRESS": re.compile(r"\b(?:домашний\s+адрес|адрес\s+проживания)\s*+[:—-]?\s*+(?P<value>[а-яё-]+,\s+[а-яё-]+\s+\d+[а-яё]?(?:/\d+)?)(?!\w)", re.IGNORECASE),
}
ADDRESS_FIELDS = re.compile(
    r"\b(?P<label>страна|город|улица|дом|квартира|почтовый\s+индекс)"
    r"(?:\s+(?P<private>клиента|проживания|регистрации|доставки))?[^\S\r\n]*+[:=][^\S\r\n]*+",
    re.IGNORECASE,
)
LITERAL_HINTS = {
    "FOREIGN_PASSPORT": ("загранпаспорт",), "BIRTH_CERTIFICATE": ("свидетельство",),
    "DRIVER_LICENSE": ("водительское", "в/у"), "PHONE": ("+",), "ADDRESS": ("адрес",),
}
PUBLIC_CONTEXT = re.compile(
    r"\b(?:(?:адрес|данные|реквизиты)\s+(?:офиса|отделения(?:\s+банка)?|банка|филиала)"
    r"|(?:офис|отделение(?:\s+банка)?|банк|филиал)\s*:)", re.IGNORECASE
)
PRIVATE_CONTEXT = re.compile(
    r"\b(?:адрес|данные|страна|город|улица|дом|квартира|почтовый\s+индекс)"
    r"\s+(?:клиента|проживания|регистрации|доставки)\b", re.IGNORECASE
)
FIELD_END = re.compile(r"[\r\n.;,!?]|\s+[А-Яа-яЁё]+\s*[:=]")
PLACE = re.compile(r"[а-яё]+(?:[- ][а-яё]+){0,4}", re.IGNORECASE)
PROSE_START = re.compile(r"\s+(?:находится|расположен[аоы]?)\b", re.IGNORECASE)
STANDALONE_NUMBER = re.compile(r"\s*+(?P<value>\d(?:[ -]?\d){9,18})\s*+")


def address_fields(text):
    """Read bounded fields without letting one match swallow the next field."""
    fields = list(ADDRESS_FIELDS.finditer(text))
    for index, match in enumerate(fields):
        start = match.end()
        end = min(start + 120, fields[index + 1].start() if index + 1 < len(fields) else len(text))
        if delimiter := FIELD_END.search(text, start, end):
            end = delimiter.start()
        value = text[start:end].rstrip(" \t")
        if not value or FIELD_PLACEHOLDER.match(value):
            continue
        prefix = re.split(r"\n\s*\n|[.;!?]", text[max(0, match.start() - 256):match.start()])[-1]
        public = list(PUBLIC_CONTEXT.finditer(prefix))
        private = list(PRIVATE_CONTEXT.finditer(prefix))
        if not match.group("private") and public and (not private or public[-1].start() > private[-1].start()):
            continue
        label = match.group("label").lower()
        if label.startswith("почтовый"):
            valid = re.fullmatch(r"\d{6}", value)
        elif label in {"дом", "квартира"}:
            valid = re.fullmatch(r"\d+[а-яё]?(?:/\d+)?", value, re.IGNORECASE)
        else:
            # Explicit narrative verbs bound known prose cases regardless of case;
            # capitalization is not evidence that an address value has ended.
            if prose := PROSE_START.search(value):
                value = value[:prose.start()]
            valid = PLACE.fullmatch(value)
        if valid:
            yield start, start + len(value), "ADDRESS"


def valid_card(digits):
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def valid_inn(digits):
    if len(set(digits)) < 2:
        return False
    def check(weights):
        return sum(int(d) * w for d, w in zip(digits, weights)) % 11 % 10
    if len(digits) == 10:
        return check((2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(digits[9])
    if len(digits) == 12:
        return (check((7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(digits[10]) and
                check((3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == int(digits[11]))
    return False


def detect_variants(text, kinds, folded=None):
    result = []
    for kind, pattern in possible_patterns(PATTERNS, kinds, folded, LITERAL_HINTS):
        for match in pattern.finditer(text):
            result.append((*match.span("value"), kind))
    if "ADDRESS" in kinds and may_contain(folded, ("страна", "город", "улица", "дом", "квартира", "почтовый")):
        result.extend(address_fields(text))
    if kinds & {"CARD", "INN"} and (match := STANDALONE_NUMBER.fullmatch(text)):
        digits = re.sub(r"\D", "", match.group("value"))
        if "CARD" in kinds and valid_card(digits):
            result.append((*match.span("value"), "CARD"))
        elif "INN" in kinds and valid_inn(digits):
            result.append((*match.span("value"), "INN"))
    return result
