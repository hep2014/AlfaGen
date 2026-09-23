from .evaluate import evaluate
from .observability import emit


def compare_policies(rows, current, candidate, detector=None):
    before = evaluate(rows, current, detector=detector)
    after = evaluate(rows, candidate, detector=detector)

    def failures(report, key):
        return {(error["id"], tuple(span)) for error in report["errors"] for span in error[key]}

    new_misses = failures(after, "missed") - failures(before, "missed")
    new_false_positives = failures(after, "unexpected") - failures(before, "unexpected")
    fixed_misses = failures(before, "missed") - failures(after, "missed")
    eligible = not new_misses and not new_false_positives
    emit("policy_comparison", status="passed" if eligible else "regression")
    return {
        "eligible_on_this_dataset": eligible,
        "examples": len(rows),
        "before": before["micro"], "after": after["micro"],
        "new_misses": len(new_misses), "new_false_positives": len(new_false_positives),
        "fixed_misses": len(fixed_misses),
        "regression_example_ids": sorted({row_id for row_id, _ in new_misses | new_false_positives}),
        "scope": "synthetic-regression-check-only",
    }
