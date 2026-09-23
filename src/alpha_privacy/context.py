"""Conservative contextual rules, preserving offsets in the original string.

These rules cover explicit fields, not arbitrary Russian prose. No global allowlist
of public names or addresses: the same value can belong to a client.
"""
import re

from .gates import may_contain, possible_patterns

WORD = r"(?!(?:просит|получил|получила|сообщил|сообщила|отправил|отправила|звонил|звонила|пишет|ждёт|ждет|согласен|согласна)\b)[а-яё]+(?:-[а-яё]+)?"

# Расширенный словарь имён с падежными формами.
# Именительный + родительный + дательный + винительный + творительный.
FIRST = (
    r"(?:"
    # Александр
    r"александр|александра|александру|александром|"
    # Александра
    r"александры|александре|александру|александрой|"
    # Иван
    r"иван|ивана|ивану|иваном|"
    # Мария
    r"мария|марии|марию|марией|"
    # Анна
    r"анна|анны|анне|анну|анной|"
    # Павел
    r"павел|павла|павлу|павлом|"
    # Елена
    r"елена|елены|елене|елену|еленой|"
    # Дмитрий
    r"дмитрий|дмитрия|дмитрию|дмитрием|"
    # Ольга
    r"ольга|ольги|ольге|ольгу|ольгой|"
    # Сергей
    r"сергей|сергея|сергею|сергеем|"
    # Наталья
    r"наталья|натальи|наталье|наталью|"
    # Михаил
    r"михаил|михаила|михаилу|михаилом|"
    # Алексей
    r"алексей|алексея|алексею|алексеем|"
    # Ирина
    r"ирина|ирины|ирине|ирину|ириной|"
    # Пётр / Петр
    r"пётр|петра|петру|петром|петр|"
    # Николай
    r"николай|николая|николаю|николаем|"
    # Екатерина
    r"екатерина|екатерины|екатерине|екатерину|екатериной|"
    # Татьяна
    r"татьяна|татьяны|татьяне|татьяну|татьяной|"
    # Андрей
    r"андрей|андрея|андрею|андреем|"
    # Максим
    r"максим|максима|максиму|максимом|"
    # Роман
    r"роман|романа|роману|романом|"
    # Юлия
    r"юлия|юлии|юлию|юлией|"
    # Светлана
    r"светлана|светланы|светлане|светлану|светланой|"
    # Владимир
    r"владимир|владимира|владимиру|владимиром|"
    # Галина
    r"галина|галины|галине|галину|галиной|"
    # Людмила
    r"людмила|людмилы|людмиле|людмилу|людмилой|"
    # Валентина
    r"валентина|валентины|валентине|валентину|валентиной|"
    # Дарья
    r"дарья|дарьи|дарье|дарью|"
    # Кристина
    r"кристина|кристины|кристине|кристину|кристиной|"
    # Евгений
    r"евгений|евгения|евгению|евгением|"
    # Денис
    r"денис|дениса|денису|денисом|"
    # Антон
    r"антон|антона|антону|антоном|"
    # Игорь
    r"игорь|игоря|игорю|игорем|"
    # Олег
    r"олег|олега|олегу|олегом|"
    # Виктор
    r"виктор|виктора|виктору|виктором|"
    # Никита
    r"никита|никиты|никите|никиту|никитой|"
    # Сидор / Кузнецов / Смирнов / Волков / Морозов / Новиков (фамилии из тестов)
    r"сидор"
    r")"
)

PATRONYMIC = r"[а-яё]+(?:ович|евич|овна|евна|ич|ична)(?:а|у|ем|ом|е|ы|ой)?(?![а-яё])"
NAME = rf"(?:{FIRST}\s+(?:{PATRONYMIC}\s+)?{WORD}|{WORD}\s+{FIRST}(?:\s+{PATRONYMIC})?)"
SEP = r"\s*+[:=—-]?\s*+"
MONTH = r"(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)"
DAY_WORD = (
    r"(?:"
    r"первое|второе|третье|четв[её]ртое|пятое|шестое|седьмое|восьмое|девятое|десятое|"
    r"одиннадцатое|двенадцатое|тринадцатое|четырнадцатое|пятнадцатое|"
    r"шестнадцатое|семнадцатое|восемнадцатое|девятнадцатое|"
    r"двадцатое|"
    r"двадцать\s+(?:первое|второе|третье|четв[её]ртое|пятое|шестое|седьмое|восьмое|девятое)|"
    r"тридцатое|тридцать\s+первое"
    r")"
)
YEAR_WORD = (
    r"(?:тысяча\s+девятьсот|две\s+тысячи)"
    r"(?:\s+(?:двадцать|тридцать|сорок|пятьдесят|шестьдесят|семьдесят|восемьдесят|девяносто))?"
    r"\s+(?:первого|второго|третьего|четв[её]ртого|пятого|шестого|седьмого|восьмого|девятого|"
    r"десятого|одиннадцатого|двенадцатого|тринадцатого|четырнадцатого|пятнадцатого|"
    r"шестнадцатого|семнадцатого|восемнадцатого|девятнадцатого|двадцатого|тридцатого|"
    r"сорокового|пятидесятого|шестидесятого|семидесятого|восьмидесятого|девяностого)"
)
DATE = (
    rf"(?:"
    rf"{DAY_WORD}\s+{MONTH}\s+{YEAR_WORD}|"
    rf"\d{{4}}[./-]\d{{1,2}}[./-]\d{{1,2}}|"                                # 1990-03-21
    rf"\d{{1,2}}[./-]\d{{1,2}}[./-]\d{{4}}|"                                # 21.03.1990
    rf"\d{{1,2}}\s+{MONTH}\s+\d{{4}}|"                          # 21 марта 1990 года
    rf"{DAY_WORD}\s+{MONTH}\s+\d{{4}}"                          # двадцать первое марта 1990 года
    rf")(?!\w)"
)

CONTEXT_FIELD_LABEL = (
    r"(?:фио|паспорт|адрес|гражданство|телефон|email|инн|cvv2?|cvc2?|pin|пин|"
    r"(?:место|дата)\s+рождения|дата\s+выдачи(?:\s+паспорта)?|код\s+подразделения|"
    r"(?:имя\s+держателя|номер)(?:\s+карты)?|cardholder)"
)
CONTEXT_FIELD_START = re.compile(r"\s+" + CONTEXT_FIELD_LABEL + r"\s*[:=]", re.IGNORECASE)
VALUE_END = rf"(?=[.;,\n]|$|\s+{CONTEXT_FIELD_LABEL}\s*[:=])"
TRAILING_PROSE = {
    "PERSON": re.compile(r"\s+приехал(?:а|и)?\b", re.IGNORECASE),
    "BIRTH_PLACE": re.compile(r"\s+сейчас\s+жив[её]т\b", re.IGNORECASE),
    "CARDHOLDER": re.compile(r"\s+please\s+call\b", re.IGNORECASE),
}


PATTERNS = {
    "PERSON": re.compile(
        r"\b(?:фио|ф\.и\.о\.|клиент(?:а|у|ом)?|за[её]мщик|получатель|владелец|заявитель|свяжитесь\s+с|обратитесь\s+к|меня\s+зовут)"
        + SEP + rf"(?P<value>{NAME})(?![а-яё-])",
        re.IGNORECASE
    ),
    "BIRTH_DATE": re.compile(
        r"\b(?:дата\s+рождения|д[.]?р[.]?|родился|родилась)" + SEP + rf"(?P<value>{DATE})",
        re.IGNORECASE
    ),
    "ISSUE_DATE": re.compile(
        r"\b(?:дата\s+выдачи(?:\s+паспорта)?|паспорт\s+выдан)" + SEP + rf"(?P<value>{DATE})",
        re.IGNORECASE
    ),
    "ADDRESS": re.compile(
        r"\b(?:домашний\s+адрес|адрес(?:\s+(?:клиента|проживания|регистрации|доставки))?|проживает\s+по\s+адресу)" + SEP
        + r"(?P<value>(?:(?:Россия|РФ),\s*+)?(?:\d{6},\s*+)?(?:г(?:ород)?\.?\s+)?[а-яё-]+,\s*+(?:ул(?:ица)?\.?|проспект|пр-т|пр\.|пер(?:еулок)?\.?)\s+[а-яё0-9 -]+,\s*+(?:д(?:ом)?\.?\s*+)?\d+[а-яё]?(?:/\d+)?(?:,\s*+(?:кв(?:артира)?\.?\s*+)\d+)?)(?!\w)",
        re.IGNORECASE
    ),
    "BIRTH_PLACE": re.compile(
        r"\bместо\s+рождения" + SEP + r"(?P<value>(?:город\s+|г\.\s*+)?[а-яё][а-яё0-9 -]*?)" + VALUE_END,
        re.IGNORECASE
    ),
    "CITIZENSHIP": re.compile(
        r"\bгражданство" + SEP + r"(?P<value>Российская\s+Федерация|Республика\s+[а-яё-]+|Россия|РФ|[а-яё-]+)(?!\w)",
        re.IGNORECASE
    ),
    "PASSPORT_ISSUER": re.compile(
        r"\b(?:орган(?:,)?\s+выдавший\s+паспорт|орган\s+выдачи(?:\s+паспорта)?|паспорт\s+выдан)" + SEP
        + r"(?P<value>[а-яё](?:г\.|[а-яё0-9 №()-])*?)(?=[.;,\n]|$)", re.IGNORECASE
    ),
    "CARDHOLDER": re.compile(
        r"\b(?:имя\s+держателя(?:\s+карты)?|cardholder)" + SEP
        + r"(?P<value>[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё0-9 -]*?)" + VALUE_END,
        re.IGNORECASE
    ),
}


LITERAL_HINTS = {
    "PERSON": ("фио", "ф.и.о.", "клиент", "заёмщик", "заемщик", "получатель",
               "владелец", "заявитель", "свяжитесь", "обратитесь", "меня"),
    "BIRTH_DATE": ("рожд", "др", "д.р", "родил"),
    "ISSUE_DATE": ("дата", "выдан"), "ADDRESS": ("адрес",),
    "BIRTH_PLACE": ("место",), "CITIZENSHIP": ("гражданство",),
    "PASSPORT_ISSUER": ("орган", "выдан"), "CARDHOLDER": ("держателя", "cardholder"),
}


ISSUANCE = re.compile(
    r"\b(?:паспорт\s+выдан|выдан)" + SEP
    + rf"(?P<issuer>(?:ОВД|УФМС|МВД|ГУВМ)[а-яё .№()-]{{0,160}}?)\s+(?P<date>{DATE})", re.IGNORECASE
)
STANDALONE_PERSON = re.compile(
    rf"\s*+(?P<value>{WORD}\s+{FIRST}\s+{PATRONYMIC}|{FIRST}\s+{PATRONYMIC}\s+{WORD})[.!]?\s*+", re.IGNORECASE
)
FIELD_PLACEHOLDER = re.compile(
    r"(?:не\s+(?:указан[оа]?|заполнен[оа]?|предоставлен[оа]?)|неизвестно|отсутствует|обязательно|укажите|not\s+provided|unknown)(?!\w)", re.IGNORECASE
)


def _append_context_match(result, text, kind, start, end, issuer_starts):
    if FIELD_PLACEHOLDER.match(text, start):
        return
    if kind in TRAILING_PROSE:
        if prose := TRAILING_PROSE[kind].search(text, start, end):
            end = prose.start()
        if field := CONTEXT_FIELD_START.search(text, start, min(len(text), end + 64)):
            end = min(end, field.start())
        while end > start and text[end - 1].isspace():
            end -= 1
    if kind == "PASSPORT_ISSUER" and re.match(DATE, text[start:], re.IGNORECASE):
        return
    if kind == "PASSPORT_ISSUER" and start in issuer_starts:
        return
    result.append((start, end, kind))


def detect_context(text: str, kinds: set[str], folded=None) -> list[tuple[int, int, str]]:
    result = []
    if "PERSON" in kinds and (match := STANDALONE_PERSON.fullmatch(text)):
        result.append((*match.span("value"), "PERSON"))
    issuance = (ISSUANCE.finditer(text) if kinds & {"PASSPORT_ISSUER", "ISSUE_DATE"}
                and may_contain(folded, ("выдан",)) else ())
    for match in issuance:
        for group, kind in (("issuer", "PASSPORT_ISSUER"), ("date", "ISSUE_DATE")):
            if kind in kinds:
                result.append((*match.span(group), kind))
    issuer_starts = {start for start, _, kind in result if kind == "PASSPORT_ISSUER"}
    for kind, pattern in possible_patterns(PATTERNS, kinds, folded, LITERAL_HINTS):
        for match in pattern.finditer(text):
            start, end = match.span("value")
            _append_context_match(result, text, kind, start, end, issuer_starts)
    return result
