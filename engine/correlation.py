"""
Correlation engine — Risk-Adaptive IAM Decision Engine
-------------------------------------------------------
Detects behavioral patterns across decision history.
Operates on persisted evidence — not on individual events.

Signals produced
----------------
  REPEATED_CRITICAL     — same user triggered critical risk N+ times
  REGULATORY_RECURRENCE — same user hit regulatory violations N+ times
  ESCALATING_RISK       — user's last N scores are strictly increasing
  PERSISTENT_NO_MFA     — user has never had MFA enabled across all records
"""

from collections import defaultdict


# ─── Signal detectors ─────────────────────────────────────────────────────────

def detect_repeated_critical(records: list[dict], threshold: int = 3) -> list[dict]:
    counts = defaultdict(int)
    for r in records:
        if r.get("risk_classification") == "CRITICO":
            counts[r["user"]] += 1
    return [
        {
            "signal"   : "REPEATED_CRITICAL",
            "user"     : user,
            "count"    : count,
            "threshold": threshold,
            "detail"   : f"{count} critical-risk decisions recorded",
        }
        for user, count in counts.items()
        if count >= threshold
    ]


def detect_regulatory_recurrence(records: list[dict], threshold: int = 2) -> list[dict]:
    counts = defaultdict(int)
    for r in records:
        if r.get("regulatory_violations"):
            counts[r["user"]] += 1
    return [
        {
            "signal"   : "REGULATORY_RECURRENCE",
            "user"     : user,
            "count"    : count,
            "threshold": threshold,
            "detail"   : f"regulatory violation in {count} decisions",
        }
        for user, count in counts.items()
        if count >= threshold
    ]


def detect_escalating_risk(records: list[dict], window: int = 3) -> list[dict]:
    by_user = defaultdict(list)
    for r in records:
        by_user[r["user"]].append(r.get("risk_score", 0))

    signals = []
    for user, scores in by_user.items():
        tail = scores[-window:]
        if len(tail) == window and all(tail[i] < tail[i+1] for i in range(len(tail)-1)):
            signals.append({
                "signal" : "ESCALATING_RISK",
                "user"   : user,
                "scores" : tail,
                "detail" : f"risk score increasing over last {window} decisions",
            })
    return signals


def detect_persistent_no_mfa(records: list[dict]) -> list[dict]:
    mfa_seen = defaultdict(set)
    for r in records:
        for factor in r.get("risk_factors", []):
            if factor.get("regra") == "R2":
                mfa_seen[r["user"]].add(False)
            else:
                mfa_seen[r["user"]].add(True)

    return [
        {
            "signal": "PERSISTENT_NO_MFA",
            "user"  : user,
            "detail": "MFA has never been enabled across all recorded decisions",
        }
        for user, states in mfa_seen.items()
        if states == {False}
    ]


# ─── Correlation runner ───────────────────────────────────────────────────────

def correlate(records: list[dict]) -> dict:
    """
    Run all signal detectors against a list of decision records.
    Returns a structured correlation report.
    """
    signals = (
        detect_repeated_critical(records)
        + detect_regulatory_recurrence(records)
        + detect_escalating_risk(records)
        + detect_persistent_no_mfa(records)
    )

    by_user = defaultdict(list)
    for s in signals:
        by_user[s["user"]].append(s)

    return {
        "total_records_analyzed": len(records),
        "signals_detected"      : len(signals),
        "by_user"               : dict(by_user),
        "all_signals"           : signals,
    }
