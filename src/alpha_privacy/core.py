from __future__ import annotations

import heapq
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Protocol

from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .context import PATTERNS as CONTEXT_PATTERNS
from .context import detect_context
from .gates import fold_for_search, possible_patterns
from .observability import emit
from .variants import EXTRA_TYPES, detect_variants


class ProcessingError(ValueError):
    """Only fixed application error codes may cross the public API boundary."""


class CombinationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str
    requires: set[str] = Field(min_length=1, max_length=8)
    max_distance: int = Field(default=128, ge=1, le=1024)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    enabled: bool = True
    detect_types: set[str]
    restore_enabled: bool = True
    session_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    mode_by_type: dict[str, Literal["token", "redact"]] = Field(default_factory=dict)
    combination_rules: list[CombinationRule] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_transformations(self):
        if self.mode_by_type.keys() - self.detect_types:
            raise ValueError("mode_type_not_detected")
        targets = set()
        for rule in self.combination_rules:
            if rule.target not in self.detect_types or rule.requires - self.detect_types:
                raise ValueError("combination_type_not_detected")
            if rule.target in rule.requires or rule.target in targets:
                raise ValueError("invalid_combination_target")
            targets.add(rule.target)
        return self


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str


class Detector(Protocol):
    supported_types: set[str]

    def detect(self, text: str, kinds: set[str]) -> list[Span]: ...


class BaselineDetector:
    """Baseline patterns, with explicit context for document numbers and secrets.

    Contextual rules mask only the named value group and preserve the field label.
    This is not full coverage of these categories or a complete DLP detector.
    """

    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "EMAIL": re.compile(r"(?<![\w.+-])[\w.+-]+\s*+@\s*+[\w-]+(?:\.[\w-]+)+", re.IGNORECASE),
        "PHONE": re.compile(r"(?<!\w)(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\w)", re.IGNORECASE),
        "INN": re.compile(r"\bинн\s*+[:№-]?\s*+(?P<value>\d{4}\s?\d{4}\s?\d{4}|\d{3}\s?\d{3}\s?\d{4}|\d{12}|\d{10})(?!\d)", re.IGNORECASE),
        "CARD": re.compile(r"\b(?:номер\s+(?:банковской\s+)?карты|карта|card(?:\s+number)?)\s*+[:№-]?\s*+(?P<value>\d(?:[ -]?\d){12,18})(?![ -]?\d)", re.IGNORECASE),
        "CVV": re.compile(r"\b(?:cvv2?|cvc2?|сvv|цвв)\b(?:[ -]код)?\s*+[:=-]?\s*+(?P<value>\d{3,4})(?!\d)", re.IGNORECASE),
        "PIN": re.compile(r"\b(?:pin|пин)\b(?:[ -]код)?(?:\s+карты)?\s*+[:=-]?\s*+(?P<value>\d{4,6})(?!\d)", re.IGNORECASE),
        "PASSPORT_RU": re.compile(r"\bпаспорт(?:\s+рф)?\s*+[:№-]?\s*+(?P<value>(?:серия\s*+)?\d{2}\s?\d{2}\s*+(?:номер\s*+|№\s*+)?\d{3}\s?\d{3}|\d{2}\s?\d{2}\s?\d{6})(?!\d)", re.IGNORECASE),
        "DEPARTMENT_CODE": re.compile(r"\bкод\s+подразделения\s*+[:№-]?\s*+(?P<value>\d{3}[ -]?\d{3})(?!\d)", re.IGNORECASE),
        "DRIVER_LICENSE": re.compile(r"\b(?:водительское\s+удостоверение|в/у)\s*+[:№-]?\s*+(?P<value>\d{2}\s?\d{2}\s?\d{6})(?!\d)", re.IGNORECASE),
    }
    supported_types: ClassVar[set[str]] = set(patterns) | set(CONTEXT_PATTERNS) | EXTRA_TYPES
    literal_hints: ClassVar[dict[str, tuple[str, ...]]] = {
        "EMAIL": ("@",), "PHONE": ("+7", "8"), "INN": ("инн",),
        "CARD": ("карт", "card"), "CVV": ("cvv", "cvc", "сvv", "цвв"),
        "PIN": ("pin", "пин"), "PASSPORT_RU": ("паспорт",),
        "DEPARTMENT_CODE": ("подразделения",), "DRIVER_LICENSE": ("водительское", "в/у"),
    }
    service_words: ClassVar[dict[str, re.Pattern[str]]] = {
        "PASSPORT_RU": re.compile(r"\b(?:серия|номер)\b\s*|№\s*", re.IGNORECASE),
        "ADDRESS": re.compile(r"\b(?:г(?:ород)?|ул(?:ица)?|проспект|пр-т|пр|пер(?:еулок)?|д(?:ом)?|кв(?:артира)?)\.?\s+", re.IGNORECASE),
        "BIRTH_PLACE": re.compile(r"\b(?:город\s+|г\.\s*)", re.IGNORECASE),
    }

    def __init__(self, field_rules=()):
        self.patterns = dict(type(self).patterns)
        self.supported_types = set(type(self).supported_types)
        if len(field_rules) > 32:
            raise ValueError("too_many_field_rules")
        for rule in field_rules:
            if rule.kind in self.supported_types:
                raise ValueError("duplicate_detector_type")
            self.patterns[rule.kind] = rule.compile()
            self.supported_types.add(rule.kind)

    def detect(self, text: str, kinds: set[str]) -> list[Span]:
        folded = fold_for_search(text)
        candidates = [Span(*span) for span in detect_context(text, kinds, folded)]
        candidates.extend(Span(*span) for span in detect_variants(text, kinds, folded))
        for kind, pattern in possible_patterns(self.patterns, kinds, folded, self.literal_hints):
            for match in pattern.finditer(text):
                start, end = match.span("value") if "value" in match.re.groupindex else match.span()
                candidates.append(Span(start, end, kind))
        candidates.sort(key=lambda s: (s.start, -(s.end - s.start), s.kind))
        result: list[Span] = []
        for span in candidates:
            if not result or span.start >= result[-1].end:
                result.append(span)
        # Preserve labels inside compound values, retaining original offsets.
        fragments = []
        for span in result:
            pattern = self.service_words.get(span.kind)
            cursor = span.start
            for label in pattern.finditer(text, span.start, span.end) if pattern else ():
                self._append_value(fragments, text, cursor, label.start(), span.kind)
                cursor = label.end()
            self._append_value(fragments, text, cursor, span.end, span.kind)
        return fragments

    @staticmethod
    def _append_value(result, text, start, end, kind):
        if kind in BaselineDetector.service_words:
            while start < end and text[start] in " ,\t\r\n":
                start += 1
            while end > start and text[end - 1] in " ,\t\r\n":
                end -= 1
        if start < end:
            result.append(Span(start, end, kind))


class VaultError(Exception):
    pass


class MemoryVault:
    """Encrypted payloads; single process only, bounded sessions, lazy TTL eviction."""

    def __init__(self, capacity: int = 1000, max_bytes: int = 128 * 1024 * 1024):
        self.cipher = Fernet(Fernet.generate_key())
        self.capacity = capacity
        self.entries: dict[str, tuple[str, float, bytes]] = {}
        self.expirations: list[tuple[float, str]] = []
        self.max_bytes = max_bytes
        self.used_bytes = 0
        self.lock = threading.Lock()

    def _evict(self) -> None:
        now = time.monotonic()
        while self.expirations and self.expirations[0][0] <= now:
            expires, key = heapq.heappop(self.expirations)
            entry = self.entries.get(key)
            if entry is not None and entry[1] == expires:
                del self.entries[key]
                self.used_bytes -= len(entry[2])

    def shorten_ttl(self, owner: str, session: str, ttl: int) -> None:
        """Release completed pairs earlier, while retaining a bounded retry window."""
        with self.lock:
            entry = self.entries.get(session)
            if entry is None or entry[0] != owner:
                return
            expires = min(entry[1], time.monotonic() + ttl)
            if expires == entry[1]:
                return
            self.entries[session] = (entry[0], expires, entry[2])
            heapq.heappush(self.expirations, (expires, session))
            # Bound stale heap nodes left by shortened deadlines and reused IDs.
            if len(self.expirations) > max(64, 2 * len(self.entries)):
                self.expirations = [(entry[1], key) for key, entry in self.entries.items()]
                heapq.heapify(self.expirations)

    def put(self, owner: str, payload: dict, ttl: int, *, session: str | None = None) -> str:
        return self.put_serialized(owner, json.dumps(payload, ensure_ascii=False).encode(), ttl, session=session)

    def put_serialized(self, owner: str, payload: bytes, ttl: int, *, session: str | None = None) -> str:
        """Internal JSON bytes from a trusted codec, encrypted without re-encoding."""
        encrypted = self.cipher.encrypt(payload)
        with self.lock:
            self._evict()
            if len(self.entries) >= self.capacity or self.used_bytes + len(encrypted) > self.max_bytes:
                raise VaultError("vault_unavailable")
            session = session or secrets.token_hex(16)
            if session in self.entries:
                raise VaultError("session_conflict")
            expires = time.monotonic() + ttl
            self.entries[session] = (owner, expires, encrypted)
            heapq.heappush(self.expirations, (expires, session))
            self.used_bytes += len(encrypted)
        return session

    def get(self, owner: str, session: str) -> dict:
        with self.lock:
            self._evict()
            entry = self.entries.get(session)
            if entry is None or entry[0] != owner:
                raise VaultError("session_unavailable")
            encrypted = entry[2]
        return json.loads(self.cipher.decrypt(encrypted))

    def encrypted_size(self, owner: str, session: str) -> int:
        """Cheap metadata check to keep large decryptions off the event loop."""
        with self.lock:
            entry = self.entries.get(session)
            return len(entry[2]) if entry is not None and entry[0] == owner else 0

    def count(self) -> int:
        """Return the number of live sessions for metrics and admission checks."""
        with self.lock:
            self._evict()
            return len(self.entries)


class SQLiteVault:
    """Encrypted multi-process vault backed by SQLite WAL.

    The evaluator sends the first and second request for a ``payload_id`` to
    arbitrary workers.  A process-local dictionary cannot preserve that
    relation.  SQLite gives all workers one atomic insert/lookup point while
    WAL keeps readers concurrent with the short write transaction.  Payloads
    remain encrypted on disk; the Fernet key is supplied by the deployment or
    stored in a separate runtime key file, never in the source tree.
    """

    def __init__(self, path: str | Path, capacity: int = 100_000,
                 max_bytes: int = 128 * 1024 * 1024,
                 key: bytes | str | None = None,
                 key_file: str | Path | None = None):
        if capacity < 0 or max_bytes < 0:
            raise ValueError("invalid_process_capacity")
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("sqlite_vault_requires_shared_path")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.capacity = capacity
        self.max_bytes = max_bytes
        self.key = self._resolve_key(key, key_file)
        try:
            self.cipher = Fernet(self.key)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_process_vault_key") from exc
        self.local = threading.local()
        self._initialize()

    @staticmethod
    def _resolve_key(key: bytes | str | None, key_file: str | Path | None) -> bytes:
        if key is not None:
            return key.encode() if isinstance(key, str) else key
        if key_file is None:
            raise ValueError("process_vault_key_required")
        path = Path(key_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as handle:
                value = Fernet.generate_key()
                handle.write(value)
                handle.flush()
                import os
                os.fsync(handle.fileno())
                return value
        except FileExistsError:
            return path.read_bytes().strip()

    def _connection(self) -> sqlite3.Connection:
        connection = getattr(self.local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.path, timeout=10.0,
                                         isolation_level=None,
                                         check_same_thread=False)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("PRAGMA busy_timeout=10000")
            self.local.connection = connection
        return connection

    def _initialize(self) -> None:
        connection = self._connection()
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS privacy_vault (
                owner TEXT NOT NULL,
                session TEXT PRIMARY KEY,
                expires_at REAL NOT NULL,
                payload BLOB NOT NULL,
                payload_size INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS privacy_vault_expiry
                ON privacy_vault (expires_at);
        """)

    @staticmethod
    def _evict(connection: sqlite3.Connection, now: float | None = None) -> None:
        connection.execute("DELETE FROM privacy_vault WHERE expires_at <= ?",
                           (time.time() if now is None else now,))

    def put(self, owner: str, payload: dict, ttl: int, *, session: str | None = None) -> str:
        return self.put_serialized(owner, json.dumps(payload, ensure_ascii=False).encode(),
                                   ttl, session=session)

    def put_serialized(self, owner: str, payload: bytes, ttl: int, *, session: str | None = None) -> str:
        encrypted = self.cipher.encrypt(payload)
        session = session or secrets.token_hex(16)
        connection = self._connection()
        for attempt in range(6):
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._evict(connection)
                existing = connection.execute(
                    "SELECT 1 FROM privacy_vault WHERE session = ?", (session,)).fetchone()
                if existing is not None:
                    connection.execute("ROLLBACK")
                    raise VaultError("session_conflict")
                count, used = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(payload_size), 0) FROM privacy_vault"
                ).fetchone()
                if count >= self.capacity or used + len(encrypted) > self.max_bytes:
                    connection.execute("ROLLBACK")
                    raise VaultError("vault_unavailable")
                connection.execute(
                    "INSERT INTO privacy_vault(owner, session, expires_at, payload, payload_size)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (owner, session, time.time() + ttl, encrypted, len(encrypted)),
                )
                connection.execute("COMMIT")
                return session
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise VaultError("session_conflict") from exc
            except sqlite3.OperationalError as exc:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if "locked" not in str(exc).lower() or attempt == 5:
                    if "locked" in str(exc).lower():
                        raise VaultError("vault_unavailable") from exc
                    raise
                # A short backoff lets the current writer finish without
                # manufacturing a 429 during a normal multi-worker burst.
                time.sleep(0.0015 * (attempt + 1))

    def get(self, owner: str, session: str) -> dict:
        connection = self._connection()
        row = connection.execute(
            "SELECT payload FROM privacy_vault WHERE owner = ? AND session = ?"
            " AND expires_at > ?",
            (owner, session, time.time()),
        ).fetchone()
        if row is None:
            raise VaultError("session_unavailable")
        try:
            return json.loads(self.cipher.decrypt(row[0]))
        except (TypeError, ValueError) as exc:
            raise VaultError("session_unavailable") from exc

    def encrypted_size(self, owner: str, session: str) -> int:
        connection = self._connection()
        row = connection.execute(
            "SELECT payload_size FROM privacy_vault WHERE owner = ? AND session = ?"
            " AND expires_at > ?",
            (owner, session, time.time()),
        ).fetchone()
        return int(row[0]) if row else 0

    def shorten_ttl(self, owner: str, session: str, ttl: int) -> None:
        connection = self._connection()
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "UPDATE privacy_vault SET expires_at = MIN(expires_at, ?)"
                " WHERE owner = ? AND session = ?",
                (time.time() + ttl, owner, session),
            )
            connection.execute("COMMIT")
        except sqlite3.Error:
            connection.execute("ROLLBACK")
            raise

    def count(self) -> int:
        connection = self._connection()
        return int(connection.execute(
            "SELECT COUNT(*) FROM privacy_vault WHERE expires_at > ?", (time.time(),)
        ).fetchone()[0])

    @property
    def used_bytes(self) -> int:
        connection = self._connection()
        return int(connection.execute(
            "SELECT COALESCE(SUM(payload_size), 0) FROM privacy_vault"
            " WHERE expires_at > ?", (time.time(),)
        ).fetchone()[0])

    def close(self) -> None:
        connection = getattr(self.local, "connection", None)
        if connection is not None:
            connection.close()
            self.local.connection = None


class Gateway:
    def __init__(self, detector: Detector, vault: MemoryVault):
        self.detector, self.vault = detector, vault

    def tokenize(self, text: str, policy: Policy) -> tuple[str, dict, dict]:
        masked, mapping, counts, _ = self.transform(text, policy, include_receipt=False)
        return masked, mapping, counts

    def transform(self, text: str, policy: Policy, *, include_receipt=True):
        from .transform import decisions_for
        if "[[PD:" in text:
            raise ProcessingError("reserved_token_syntax")
        emit("stage_started", stage="detection", policy_version=policy.version)
        spans = self.detector.detect(text, policy.detect_types)
        decisions = []
        emit("stage_finished", stage="detection", status="ok")
        emit("stage_started", stage="tokenization")
        namespace = secrets.token_hex(16)
        mapping, counts, parts, tokens_by_value = {}, {}, [], {}
        cursor = 0
        for span, decision in zip(spans, decisions_for(text, spans, policy)):
            if include_receipt:
                decisions.append(decision)
            if not decision["protected"]:
                continue
            value = text[span.start:span.end]
            if decision["mode"] == "redact":
                token = f"[REDACTED:{span.kind}]"
            else:
                # Equal values share one token only inside this request; never across sessions.
                token = tokens_by_value.get((span.kind, value))
                if token is None:
                    token = f"[[PD:{namespace}:{span.kind}:{len(mapping)}]]"
                    tokens_by_value[span.kind, value] = token
                    mapping[token] = value
            counts[span.kind] = counts.get(span.kind, 0) + 1
            parts.extend([text[cursor:span.start], token])
            cursor = span.end
        parts.append(text[cursor:])
        masked = "".join(parts)
        emit("stage_finished", stage="tokenization", status="ok", types=counts)
        return masked, mapping, counts, decisions

    def mask(self, owner: str, text: str, policy: Policy) -> dict:
        masked, mapping, counts, decisions = self.transform(text, policy)
        emit("stage_started", stage="vault_write")
        session = self.vault.put(owner, {"mapping": mapping}, policy.session_ttl_seconds) if policy.restore_enabled else None
        emit("stage_finished", stage="vault_write", status="ok" if session else "skipped")
        return {"text": masked, "session_id": session, "detected_types": counts,
                "policy_version": policy.version,
                "receipt": {"decisions": decisions,
                            "all_detected_protected": all(d["protected"] for d in decisions),
                            "irreversible_fragments": sum(d["mode"] == "redact" and d["protected"] for d in decisions)}}

    def restore(self, owner: str, session: str, text: str) -> str:
        emit("stage_started", stage="restoration")
        mapping = self.vault.get(owner, session)["mapping"]
        # Validate all control tokens, then substitute once: restored values are never re-parsed.
        pattern = r"\[\[PD:[^\[\]\r\n]+\]\]"
        tokens = re.findall(pattern, text)
        if any(token not in mapping for token in tokens) or "[[PD:" in re.sub(pattern, "", text):
            raise ProcessingError("unknown_or_damaged_token")
        result = re.sub(pattern, lambda m: mapping[m.group()], text)
        emit("stage_finished", stage="restoration", status="ok")
        return result
