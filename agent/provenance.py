"""D: explicit, lossless raw-reference transport and citation validation.

References are opaque strings: never rewrite an upstream raw_ref, infer a
reference from prose, or attach every observed log to an uncited claim.
"""
from __future__ import annotations

from typing import Any, Dict, List


def references(value: Dict[str, Any], *, seed: bool = False) -> List[str]:
    result = []
    for key in (("raw_ref", "raw_refs", "evidence_refs") if seed else ("raw_ref", "raw_refs")):
        refs = value.get(key)
        if refs is None:
            continue
        if key == "raw_ref":
            refs = [refs]
        if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
            raise ValueError(f"{key} must contain non-empty string references")
        result.extend(refs)
    return list(dict.fromkeys(result))


def observed_references(result: Dict[str, Any]) -> List[str]:
    return list(observed_reference_groups(result))


def observed_reference_groups(result: Dict[str, Any]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for record in result.get("records", []):
        for item in [record, *record.get("nodes", [])]:
            refs = references(item)
            for ref in refs:
                groups[ref] = list(dict.fromkeys(groups.get(ref, []) + refs))
    return groups


def validate_citations(value: Dict[str, Any], known: List[str]) -> tuple[List[str], List[str]]:
    refs = references(value)
    return [ref for ref in refs if ref in known], [ref for ref in refs if ref not in known]


def provenance_report(state: Any) -> Dict[str, Any]:
    evidence = state.evidence + state.contradicting_evidence
    missing = [e.evidence_id for e in evidence if not e.raw_refs]
    issues = list(state.provenance_issues)
    status = "passed" if state.raw_refs else "unavailable"
    if issues or missing:
        status = "incomplete"
    return {"status": status, "raw_ref_count": len(state.raw_refs),
            "seed_raw_refs": references(state.seed, seed=True),
            "evidence_without_raw_refs": missing, "issues": issues}
