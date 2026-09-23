"""Exact typed span metrics; missing categories remain in the denominator."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from .core import BaselineDetector, Gateway, MemoryVault, Policy
from .observability import quiet_audit
from .synthetic import LABELS, validate


def scores(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


@quiet_audit()
def evaluate(rows, kinds=None, detector=None):
    detector = detector or BaselineDetector()
    validate(rows, supported_types=detector.supported_types)
    gateway = Gateway(detector, MemoryVault(capacity=max(1, len(rows))))
    kinds = detector.supported_types if kinds is None else kinds
    if kinds - detector.supported_types:
        raise ValueError("unsupported_types")
    policy = Policy(version="eval-v1", detect_types=kinds)
    tp, fp, fn = Counter(), Counter(), Counter()
    errors, exact, roundtrip, uncovered = [], 0, 0, 0
    for row in rows:
        expected = {(e["start"], e["end"], e["type"]) for e in row["entities"]}
        spans = detector.detect(row["text"], kinds)
        predicted = {(s.start, s.end, s.kind) for s in spans}
        tp.update(s[2] for s in predicted & expected)
        fp.update(s[2] for s in predicted - expected)
        fn.update(s[2] for s in expected - predicted)
        exact += expected == predicted
        # A correctly typed span is stricter than complete coverage of its characters.
        covered = {i for s in spans for i in range(s.start, s.end)}
        uncovered += any(any(i not in covered for i in range(start, end)) for start, end, _ in expected)
        masked = gateway.mask("evaluation", row["text"], policy)
        roundtrip += gateway.restore("evaluation", masked["session_id"], masked["text"]) == row["text"]
        if expected != predicted:
            errors.append({"id": row["id"], "missed": sorted(expected - predicted), "unexpected": sorted(predicted - expected)})
    return {"examples": len(rows), "micro": scores(sum(tp.values()), sum(fp.values()), sum(fn.values())),
            "by_type": {kind: scores(tp[kind], fp[kind], fn[kind]) for kind in sorted(set(LABELS) | set(tp) | set(fp) | set(fn))},
            "exact_examples": exact, "roundtrip_exact": roundtrip,
            "examples_with_uncovered_sensitive_characters": uncovered,
            "unsupported_types": sorted(set(LABELS) - detector.supported_types), "errors": errors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/synthetic/v1")
    parser.add_argument("--output", default="reports/quality-v1.json")
    args = parser.parse_args()
    result = {}
    for split in ["train", "dev", "test", "challenge"]:
        source = (Path(args.data) / f"{split}.jsonl").read_bytes()
        rows = [json.loads(line) for line in source.decode("utf-8").splitlines() if line]
        result[split] = evaluate(rows)
        result[split]["dataset_sha256"] = hashlib.sha256(source).hexdigest()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    for split, metrics in result.items():
        print(split, json.dumps({k: v for k, v in metrics.items() if k not in {"errors", "by_type"}}, ensure_ascii=True))


if __name__ == "__main__":
    main()
