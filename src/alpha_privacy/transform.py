"""Explainable transformations; decisions contain offsets and reasons, never values."""
import re
from bisect import bisect_left
from collections import defaultdict
from itertools import islice

BOUNDARY = re.compile(r"[.!?;\r\n]")


def decisions_for(text, spans, policy):
    rules = {rule.target: rule for rule in policy.combination_rules}
    by_kind = defaultdict(list)
    if rules:
        for span in spans:
            by_kind[span.kind].append(span)

    def nearby(span, required, distance):
        candidates = by_kind[required]
        start = bisect_left(candidates, span.start - distance, key=lambda s: s.end)
        for other in islice(candidates, start, None):
            if other.start > span.end + distance:
                break
            gap = text[min(span.end, other.end):max(span.start, other.start)]
            if len(gap) <= distance and not BOUNDARY.search(gap):
                return True
        return False

    for span in spans:
        rule = rules.get(span.kind)
        protect = rule is None or all(nearby(span, kind, rule.max_distance) for kind in rule.requires)
        yield {"start": span.start, "end": span.end, "type": span.kind,
                          "protected": protect, "mode": policy.mode_by_type.get(span.kind, "token"),
                          "reason": "default_protection" if rule is None else
                                    "combination_present" if protect else "combination_missing"}
