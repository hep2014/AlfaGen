"""Local policy simulations containing offsets and decisions, never source values."""
from .core import ProcessingError
from .transform import decisions_for


def uncovered_fragments(fragments, coverage):
    """Subtract sorted, non-overlapping coverage from sorted typed fragments."""
    result = []
    index = 0
    for fragment in fragments:
        start, end = fragment["start"], fragment["end"]
        while index < len(coverage) and coverage[index]["end"] <= start:
            index += 1
        cursor = index
        while cursor < len(coverage) and coverage[cursor]["start"] < end:
            covered = coverage[cursor]
            if covered["start"] > start:
                result.append({**fragment, "start": start, "end": min(end, covered["start"])})
            start = max(start, covered["end"])
            if start >= end:
                break
            cursor += 1
        if start < end:
            result.append({**fragment, "start": start, "end": end})
    return result


def simulate_policy(text, policy, detector, reference):
    admitted = policy.enabled
    # Policy-specific detection is essential: excluded types can expose previously
    # overlapping matches. Filtering the reference pass would simulate incorrectly.
    spans = detector.detect(text, policy.detect_types) if admitted else []
    decisions = [
        {**decision, "restorable": decision["protected"] and decision["mode"] == "token" and policy.restore_enabled}
        for decision in decisions_for(text, spans, policy)
    ]
    protected = [decision for decision in decisions if decision["protected"]]
    return {
        "status": "would_process" if admitted else "system_disabled",
        "restore_enabled": policy.restore_enabled,
        "session_ttl_seconds": policy.session_ttl_seconds,
        "decisions": decisions,
        "detected_fragments": len(decisions),
        "protected_fragments": len(protected),
        "irreversible_fragments": sum(not decision["restorable"] for decision in protected),
        "excluded_types": sorted({span["type"] for span in reference} - policy.detect_types),
        "unprotected_reference_fragments": uncovered_fragments(reference, protected) if admitted else None,
    }


def preview_policy(text, current, candidate, detector):
    if "[[PD:" in text:
        raise ProcessingError("reserved_token_syntax")
    if (current.detect_types | candidate.detect_types) - detector.supported_types:
        raise ProcessingError("unsupported_types")
    reference = [{"start": span.start, "end": span.end, "type": span.kind}
                 for span in detector.detect(text, detector.supported_types)]
    before = simulate_policy(text, current, detector, reference)
    after = simulate_policy(text, candidate, detector, reference)
    comparable = current.enabled and candidate.enabled
    new_misses = (uncovered_fragments(after["unprotected_reference_fragments"],
                                    before["unprotected_reference_fragments"]) if comparable else None)
    fixed_misses = (uncovered_fragments(before["unprotected_reference_fragments"],
                                      after["unprotected_reference_fragments"]) if comparable else None)
    return {
        "scope": "local-policy-preview",
        "coverage_basis": "same-detector-findings-only",
        "quality_guarantee": False,
        "reference_findings": reference,
        "current": before,
        "candidate": after,
        "comparison": {
            "comparable": comparable,
            "new_misses": new_misses,
            "new_missed_fragments": len(new_misses) if comparable else None,
            "new_missed_characters": sum(span["end"] - span["start"] for span in new_misses) if comparable else None,
            "fixed_misses": fixed_misses,
            "protected_fragments_delta": after["protected_fragments"] - before["protected_fragments"],
            "irreversible_fragments_delta": after["irreversible_fragments"] - before["irreversible_fragments"],
        },
    }
