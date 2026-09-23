"""Bounded cache of offsets only, never texts, values, or reusable mask tokens."""
import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict


class CachedDetector:
    def __init__(self, detector, capacity=4096, ttl=60, max_chars=16_384, max_spans=256):
        self.detector = detector
        self.supported_types = detector.supported_types
        self.capacity, self.ttl = capacity, ttl
        self.max_chars, self.max_spans = max_chars, max_spans
        self.key = secrets.token_bytes(32)
        self.entries = OrderedDict()
        self.lock = threading.Lock()
        self.hits = self.misses = self.bypasses = 0

    def detect(self, text, kinds):
        if len(text) > self.max_chars or self.capacity == 0:
            with self.lock:
                self.bypasses += 1
            return self.detector.detect(text, kinds)
        digest = hmac.digest(self.key, text.encode("utf-8"), hashlib.sha256)  # NOSONAR: S4790 — cache key, not a password.
        key = (digest, frozenset(kinds))
        with self.lock:
            entry = self.entries.get(key)
            if entry is not None and entry[0] > time.monotonic():
                self.entries.move_to_end(key)
                self.hits += 1
                return list(entry[1])
            if entry is not None:
                del self.entries[key]
            self.misses += 1
        spans = self.detector.detect(text, kinds)
        if len(spans) <= self.max_spans:
            with self.lock:
                self.entries[key] = (time.monotonic() + self.ttl, tuple(spans))
                self.entries.move_to_end(key)
                while len(self.entries) > self.capacity:
                    self.entries.popitem(last=False)
        return spans

    def stats(self):
        with self.lock:
            return {"hits": self.hits, "misses": self.misses, "bypasses": self.bypasses,
                    "entries": len(self.entries)}
