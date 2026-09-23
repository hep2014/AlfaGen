"""Deterministic labelled fixtures; no external sources or model-generated labels."""
import argparse
import json
import random
from pathlib import Path

LABELS = {
    "PERSON": "ФИО", "BIRTH_DATE": "Дата рождения", "BIRTH_PLACE": "Место рождения",
    "PASSPORT_RU": "Паспорт РФ", "CITIZENSHIP": "Гражданство", "PASSPORT_ISSUER": "Орган выдачи паспорта",
    "DEPARTMENT_CODE": "Код подразделения", "ISSUE_DATE": "Дата выдачи паспорта",
    "DRIVER_LICENSE": "Водительское удостоверение", "ADDRESS": "Адрес клиента",
    "EMAIL": "Email", "PHONE": "Телефон", "INN": "ИНН", "CARD": "Номер карты",
    "CVV": "CVV", "PIN": "PIN", "CARDHOLDER": "Имя держателя карты",
}

NAMES = ["Александр", "Мария", "Иван", "Анна", "Павел", "Елена"]


def record(identifier, split, family, parts, tags=()):
    text, entities = "", []
    for part in parts:
        if isinstance(part, tuple):
            kind, value = part
            entities.append({"start": len(text), "end": len(text) + len(value), "type": kind, "value": value})
            text += value
        else:
            text += part
    return {"id": identifier, "split": split, "family": family, "synthetic": True,
            "tags": list(tags), "text": text, "entities": entities}


def _build_values(rng, split_index, n, serial):
    digits = f"{rng.randrange(10**9):09d}"
    date = f"{1+n%27:02d}.{1+n%12:02d}.{1970+serial%40}"
    if n % 3 == 1:
        date = f"{1970+serial%40}-{1+n%12:02d}-{1+n%27:02d}"
    elif n % 3 == 2:
        date = f"{1+n%27} марта {1970+serial%40} года"
    return {
        "PERSON": f"{NAMES[n%len(NAMES)]} {'Образцова' if n%2 else 'Фантазиев'}",
        "BIRTH_DATE": date, "BIRTH_PLACE": f"город Тестоград-{serial}",
        "PASSPORT_RU": f"серия 00 00 номер {serial:06d}",
        "CITIZENSHIP": "Российская Федерация",
        "PASSPORT_ISSUER": f"Учебный отдел вымышленных документов № {serial}",
        "DEPARTMENT_CODE": f"000-{serial:03d}", "ISSUE_DATE": date,
        "DRIVER_LICENSE": f"00 00 {serial:06d}",
        "ADDRESS": f"г. Тестоград, ул. Вымышленная, д. {serial}, кв. {n+1}",
        "EMAIL": f"fixture-{serial}@example.org", "PHONE": f"+7 (000) {digits[:3]}-{digits[3:5]}-{digits[5:7]}",
        "INN": f"00{serial:010d}", "CARD": f"0000 0000 0000 {serial:04d}",
        "CVV": f"{n+100:03d}", "PIN": f"{serial+1000:04d}",
        "CARDHOLDER": f"TEST PERSON {serial}",
    }


def _build_parts(kind, value, serial, n, split):
    label = LABELS[kind]
    pieces = [(kind, value)]
    if kind in {"BIRTH_DATE", "ISSUE_DATE"} and value.endswith(" года"):
        pieces = [(kind, value[:-5]), " года"]
    elif kind == "BIRTH_PLACE":
        pieces = ["город ", (kind, f"Тестоград-{serial}")]
    elif kind == "PASSPORT_RU":
        pieces = ["серия ", (kind, "00 00"), " номер ", (kind, f"{serial:06d}")]
    elif kind == "ADDRESS":
        pieces = ["г. ", (kind, "Тестоград"), ", ул. ", (kind, "Вымышленная"),
                  ", д. ", (kind, str(serial)), ", кв. ", (kind, str(n+1))]
    if split == "train":
        return [label + ": ", *pieces, "."]
    transform = str.lower if split == "dev" else str.upper
    pieces = [(part[0], transform(part[1])) if isinstance(part, tuple)
              else transform(part) for part in pieces]
    return (["Анкета для проверки\n" + label.upper() + ": ", *pieces, "; конец поля."]
            if split == "dev" else
            ["Синтетическое обращение. " + label.lower() + " ", *pieces, "\nПросьба обработать."])


def generate(seed=20260922, per_type=12):
    # NOSONAR: S2245 — deterministic fixture generator, not cryptography.
    rng = random.Random(seed)
    rows = []
    for split_index, split in enumerate(["train", "dev", "test"]):
        for n in range(per_type):
            serial = split_index * per_type + n + 1
            values = _build_values(rng, split_index, n, serial)
            for kind, value in values.items():
                parts = _build_parts(kind, value, serial, n, split)
                rows.append(record(f"{split}-{kind}-{n:03d}", split, f"{split}-field", parts, ["explicit_field"]))
        rows.extend([
            record(f"{split}-public-person", split, f"{split}-contrast", ["Поэт Александр Пушкин написал стихотворение."], ["public_person", "negative"]),
            record(f"{split}-private-person", split, f"{split}-contrast", ["Клиент ", ("PERSON", "Александр Пушкин"), "; просит ответить."], ["namesake"]),
            record(f"{split}-office", split, f"{split}-contrast", ["Адрес отделения банка: г. Тестоград, ул. Вымышленная, д. 1."], ["public_address", "negative"]),
            record(f"{split}-home", split, f"{split}-contrast", ["Адрес проживания: ", "г. ", ("ADDRESS", "Тестоград"), ", ул. ", ("ADDRESS", "Вымышленная"), ", д. ", ("ADDRESS", "1"), "."], ["private_address"]),
            record(f"{split}-mixed", split, f"{split}-mixed", ["Поэт Александр Пушкин известен. Клиент ", ("PERSON", "Александр Пушкин"), "; дата рождения: ", ("BIRTH_DATE", "6 июня 1990"), "; email: ", ("EMAIL", f"mixed-{split}@example.org"), "."], ["mixed_context"]),
        ])
        for n, text in enumerate(["Дата встречи: 01.02.2026.", "Релиз выдан 2026-03-01.", "Клиент просит помощь.", "В очереди 123 человека.", "Артикул 1234567890."]):
            rows.append(record(f"{split}-negative-{n}", split, f"{split}-negative", [text], ["negative"]))
    challenges = [
        ["Меня зовут ", ("PERSON", "Александр Фантазиев"), "."],
        ["Свяжитесь с ", ("PERSON", "Иваном Фантазиевым"), "."],
        ["ДР: ", ("BIRTH_DATE", "03.04.1990"), "."],
        ["Дата рождения: ", ("BIRTH_DATE", "третье апреля тысяча девятьсот девяностого"), " года."],
        ["Домашний адрес — ", ("ADDRESS", "Тестоград, Вымышленная 8"), "."],
        ["ФИО: ", ("PERSON", "Александр Фантазиев"), "; email: ", ("EMAIL", "challenge@example.org"), "."],
    ]
    for n, parts in enumerate(challenges):
        rows.append(record(f"challenge-{n}", "challenge", "challenge-prose", parts, ["held_out_challenge"]))
    return rows


def validate(rows, supported_types=None):
    supported_types = set(LABELS) if supported_types is None else supported_types
    ids = set()
    for row in rows:
        if row["id"] in ids:
            raise ValueError("duplicate_id")
        ids.add(row["id"])
        end = 0
        for entity in row["entities"]:
            start, stop = entity["start"], entity["end"]
            if not end <= start < stop <= len(row["text"]) or row["text"][start:stop] != entity["value"]:
                raise ValueError("invalid_annotation")
            if entity["type"] not in supported_types:
                raise ValueError("unknown_annotation_type")
            end = stop


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/synthetic/v2")
    parser.add_argument("--seed", type=int, default=20260922)
    args = parser.parse_args()
    rows = generate(args.seed)
    validate(rows)
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=True)
    for split in ["train", "dev", "test", "challenge"]:
        selected = [row for row in rows if row["split"] == split]
        (directory / f"{split}.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in selected), encoding="utf-8")
    (directory / "manifest.json").write_text(json.dumps({"version": 2, "seed": args.seed, "rows": len(rows), "types": list(LABELS)}, indent=2), encoding="utf-8")
    print(f"Generated and validated {len(rows)} examples")


if __name__ == "__main__":
    main()
