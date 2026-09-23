"""Adaptive exact-pair storage: sparse replacements instead of two large texts."""
import hashlib
import hmac
import json
import re
import secrets

TOKEN = re.compile(r"\[\[PD:[^\[\]\r\n]+\]\]")


def encode(record):
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def signature(secret, pair_key, text):
    digest = hmac.new(bytes.fromhex(secret), b"exact-pair-v1\0" + pair_key.encode("ascii"), hashlib.sha256)  # NOSONAR: S4790 — integrity tag, not a password.
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def pack_pair(original, masked, mapping, pair_key):
    """Return ready-to-encrypt JSON; never lose reversibility for custom policies."""
    full = {"original": original, "masked": masked}
    if len(original) + len(masked) <= 8192:
        return encode(full)

    replacements = list(mapping.items())
    indexes = {token: index for index, (token, _) in enumerate(replacements)}
    patches = []
    original_cursor = masked_cursor = 0
    for match in TOKEN.finditer(masked):
        token = match.group()
        if token not in indexes:
            return encode(full)
        gap = masked[masked_cursor:match.start()]
        value = mapping[token]
        if not original.startswith(gap, original_cursor):
            return encode(full)
        original_cursor += len(gap)
        if not original.startswith(value, original_cursor):
            return encode(full)
        patches.append((len(gap), indexes[token]))
        original_cursor += len(value)
        masked_cursor = match.end()
    if original[original_cursor:] != masked[masked_cursor:]:
        # e.g. direct ProcessService use with a redact policy: the full pair is
        # still exactly reversible, even when the transformation mapping is not.
        return encode(full)

    secret = secrets.token_hex(32)
    compact = encode({"format": "patch-v1", "secret": secret,
                      "original_tag": signature(secret, pair_key, original),
                      "masked_tag": signature(secret, pair_key, masked),
                      "replacements": replacements, "patches": patches})
    # UTF-8 full JSON cannot be shorter than original's character count.
    # Avoid serializing the large full pair at all for clearly sparse records.
    if len(compact) < len(original):
        return compact
    full_bytes = encode(full)
    return compact if len(compact) < len(full_bytes) else full_bytes


def apply_patches(record, text, restore):
    parts = []
    cursor = 0
    for gap, index in record["patches"]:
        token, value = record["replacements"][index]
        end = cursor + gap
        parts.extend((text[cursor:end], value if restore else token))
        cursor = end + len(token if restore else value)
    parts.append(text[cursor:])
    return "".join(parts)


def replay_pair(record, text, pair_key):
    """Return (result, completed), or None for a conflicting input."""
    if record.get("format") == "patch-v1":
        tag = signature(record["secret"], pair_key, text)
        # Mask first preserves no-PII pair completion when both texts are equal.
        if hmac.compare_digest(tag, record["masked_tag"]):
            return apply_patches(record, text, restore=True), True
        if hmac.compare_digest(tag, record["original_tag"]):
            return apply_patches(record, text, restore=False), False
    else:
        if text == record["masked"]:
            return record["original"], True
        if text == record["original"]:
            return record["masked"], False
    return None
