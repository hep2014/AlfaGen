import pytest

from alpha_privacy.core import BaselineDetector, Gateway, MemoryVault, Policy
from alpha_privacy.robustness import generate_robustness


@pytest.mark.parametrize("row", generate_robustness(), ids=lambda row: row["id"])
def test_labelled_variants_and_negatives(row):
    text = row["text"]
    gateway = Gateway(BaselineDetector(), MemoryVault())
    spans = gateway.detector.detect(text, gateway.detector.supported_types)
    assert [(s.start, s.end, s.kind) for s in spans] == [
        (e["start"], e["end"], e["type"]) for e in row["entities"]]
    result = gateway.mask("test", text, Policy(version="1", detect_types=gateway.detector.supported_types))
    assert gateway.restore("test", result["session_id"], result["text"]) == text
