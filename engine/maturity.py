"""
Maturity report — Risk-Adaptive IAM Decision Engine
----------------------------------------------------
Reads persisted decision evidence and produces a maturity assessment.

Metrics
-------
  decisions by zone          — dynamic / conditioned / restricted
  decisions by basis         — risk_score vs regulatory_constraint
  most activated risk rules  — R1 / R2 / R3 / R4
  most triggered constraints — C1 / C2
  % decisions outside risk tolerance (CRITICAL or REQUIRE_ACTION)
  maturity state             — Stable / Unstable / Critical
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from persistence import load_all, DEFAULT_DIR
from correlation import correlate


# ─── Maturity state thresholds ────────────────────────────────────────────────

CRITICAL_THRESHOLD  = 0.40   # >40% decisions critical  → maturity Critical
UNSTABLE_THRESHOLD  = 0.20   # >20% decisions critical  → maturity Unstable


# ─── Aggregators ─────────────────────────────────────────────────────────────

def _zone_distribution(records):
    counts = Counter(r.get("applied_zone", "unknown") for r in records)
    total  = len(records) or 1
    return {zone: {"count": c, "pct": round(c / total * 100, 1)} for zone, c in counts.items()}


def _basis_distribution(records):
    counts = Counter(r.get("decision_basis", "unknown") for r in records)
    total  = len(records) or 1
    return {b: {"count": c, "pct": round(c / total * 100, 1)} for b, c in counts.items()}


def _decision_distribution(records):
    counts = Counter(r.get("decision", "unknown") for r in records)
    total  = len(records) or 1
    return {d: {"count": c, "pct": round(c / total * 100, 1)} for d, c in counts.items()}


def _rule_activation(records):
    rule_counts = Counter()
    for r in records:
        for factor in r.get("risk_factors", []):
            rule_counts[factor["regra"]] += 1
    return dict(rule_counts.most_common())


def _constraint_activation(records):
    constraint_counts = Counter()
    for r in records:
        for v in r.get("regulatory_violations", []):
            key = f"{v['constraint']} ({v['framework']})"
            constraint_counts[key] += 1
    return dict(constraint_counts.most_common())


def _pct_outside_tolerance(records):
    if not records:
        return 0.0
    outside = sum(
        1 for r in records
        if r.get("risk_classification") in ("CRITICO",)
        or r.get("decision") in ("BLOCK_OR_ENFORCE_MFA", "REQUIRE_ACTION")
    )
    return round(outside / len(records) * 100, 1)


def _maturity_state(pct_outside: float) -> str:
    if pct_outside >= CRITICAL_THRESHOLD * 100:
        return "CRITICO"
    if pct_outside >= UNSTABLE_THRESHOLD * 100:
        return "UNSTABLE"
    return "STABLE"


# ─── Report builder ───────────────────────────────────────────────────────────

def build_report(evidence_dir: Path = DEFAULT_DIR) -> dict:
    records = load_all(evidence_dir)

    if not records:
        return {"error": "no evidence records found", "evidence_dir": str(evidence_dir)}

    pct_outside    = _pct_outside_tolerance(records)
    maturity_state = _maturity_state(pct_outside)
    correlation    = correlate(records)

    return {
        "generated_at"        : datetime.now(timezone.utc).isoformat(),
        "model_version"       : records[-1].get("model_version", "unknown"),
        "rule_version"        : records[-1].get("rule_version", "unknown"),
        "total_decisions"     : len(records),
        "maturity_state"      : maturity_state,
        "pct_outside_tolerance": pct_outside,
        "zone_distribution"   : _zone_distribution(records),
        "basis_distribution"  : _basis_distribution(records),
        "decision_distribution": _decision_distribution(records),
        "rule_activation"     : _rule_activation(records),
        "constraint_activation": _constraint_activation(records),
        "correlation_signals" : correlation["signals_detected"],
        "correlation_by_user" : correlation["by_user"],
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    evidence_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIR
    report       = build_report(evidence_dir)

    print(json.dumps(report, indent=2))
