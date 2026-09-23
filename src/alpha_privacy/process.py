"""Exact pair protocol used by the evaluator; no LLM call on this path."""
import hashlib
import threading

from .core import Gateway, MemoryVault, Policy, ProcessingError, SQLiteVault, VaultError
from .pair_codec import pack_pair, replay_pair


class PayloadConflict(ProcessingError):
    pass


class ProcessService:
    def __init__(self, gateway: Gateway, policy: Policy,
                 vault: MemoryVault | SQLiteVault, completed_ttl=60):
        self.gateway, self.policy, self.vault = gateway, policy, vault
        self.completed_ttl = completed_ttl
        # Bounded locks serialize retries of the same ID, without a global
        # detection/encryption lock or an unbounded per-ID lock registry.
        self.locks = [threading.Lock() for _ in range(256)]

    def can_inline(self, payload_id: str, payload: str) -> bool:
        if len(payload) > 4096:
            return False
        key = hashlib.sha256(payload_id.encode()).hexdigest()  # NOSONAR: S4790 — identifier key, not a password.
        return self.vault.encrypted_size("evaluator", key) <= 32_768

    def _replay_or_conflict(self, key, payload):
        entry = self.vault.get("evaluator", key)
        replay = replay_pair(entry, payload, key)
        if replay is None:
            raise PayloadConflict("payload_id_conflict")
        result, completed = replay
        if completed:
            self.vault.shorten_ttl("evaluator", key, self.completed_ttl)
        return result, {}

    def process(self, payload_id: str, payload: str, *, blocking=True) -> tuple[str, dict]:
        key = hashlib.sha256(payload_id.encode()).hexdigest()  # NOSONAR: S4790 — identifier key, not a password.
        lock = self.locks[int(key[:2], 16)]
        if not lock.acquire(blocking=blocking):
            raise VaultError("process_busy")
        try:
            if not blocking and self.vault.encrypted_size("evaluator", key) > 32_768:
                raise VaultError("process_busy")
            try:
                entry = self.vault.get("evaluator", key)
            except VaultError as exc:
                if str(exc) != "session_unavailable":
                    raise
                entry = None
            if entry is not None:
                return self._replay_or_conflict(key, payload)
            if len(payload) > 1_000_000:
                raise ProcessingError("text_too_large")
            masked, mapping, counts = self.gateway.tokenize(payload, self.policy)
            try:
                self.vault.put_serialized("evaluator", pack_pair(payload, masked, mapping, key),
                                          self.policy.session_ttl_seconds, session=key)
            except VaultError as exc:
                if str(exc) != "session_conflict":
                    raise
                return self._replay_or_conflict(key, payload)
            return masked, counts
        finally:
            lock.release()
