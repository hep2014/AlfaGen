"""Provider contract. Only local implementations are permitted until coverage is validated."""
from typing import Protocol


class LLMProvider(Protocol):
    name: str
    local_only: bool

    def generate(self, protected_text: str) -> str: ...


class LocalEcho:
    name = "local-echo"
    local_only = True

    def generate(self, protected_text: str) -> str:
        return protected_text
