"""Necessary literal hints skip impossible regex passes on long inputs.

Hints only select rules; the original regex still decides spans in the original
text. Missing hints and exceptional Unicode casing always take the full path.
"""


def fold_for_search(text):
    if len(text) <= 4096 or any(char in text for char in "İıſ"):
        # These characters have extra ASCII equivalences under Python re.I.
        return None
    # casefold also normalizes historical Cyrillic forms matched by re.I;
    # lower alone would miss e.g. U+1C83 in a passport label.
    return text.casefold()


def may_contain(folded, markers):
    return folded is None or not markers or any(marker in folded for marker in markers)


def possible_patterns(patterns, kinds, folded, hints):
    for kind in sorted(kinds & patterns.keys()):
        if may_contain(folded, hints.get(kind)):
            yield kind, patterns[kind]
