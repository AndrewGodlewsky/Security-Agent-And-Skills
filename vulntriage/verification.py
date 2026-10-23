"""Compare fresh observations without mistaking disappearance for a fix."""
from datetime import datetime
from .common import now
from .assessment import fresh


def later(after, before):
    try:
        return datetime.fromisoformat(after.replace("Z", "+00:00")) > datetime.fromisoformat(before.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        return False


def verify(before, after):
    if before["advisory_digest"] != after["advisory_digest"]:
        raise ValueError("Advisory changed. Reassess both inventories against the same current advisory first.")
    same_scope = set(before["scopes"]) == set(after["scopes"])
    lookup = {(f["asset_key"], f["target"]): f for f in after["findings"]}
    results = []
    for old in before["findings"]:
        if old["applicability"] != "affected":
            continue
        new = lookup.get((old["asset_key"], old["target"]))
        state, reason = "unknown", "Affected observation disappeared; removal or lost coverage needs explicit evidence"
        if not same_scope:
            reason = "Collection scopes changed"
        elif new:
            if not fresh(new.get("observed_at")) or not later(new.get("observed_at"), old.get("observed_at")):
                reason = "No fresh observation after the baseline"
            elif new["applicability"] == "affected":
                state, reason = "still_affected", "Fresh observation remains in the affected version set"
            elif new["applicability"] == "not_affected":
                state = "component_fix_verified"
                reason = ("Fresh " + new["evidence_kind"] + " version is outside affected rules; "
                          "running processes/deployments and exposure require separate verification")
            else:
                reason = "New applicability assessment is inconclusive"
        results.append(dict(asset_key=old["asset_key"], location=old["location"], state=state, reason=reason))
    incomplete = bool(after.get("gaps") or after.get("missing_targets") or
                      any(f["applicability"] in ("unknown", "affected") for f in after["findings"]))
    return dict(schema_version=1, verified_at=now(), advisory_id=before["advisory_id"],
                results=results, runtime_verification="not_performed",
                overall="needs_follow_up" if incomplete or not results or
                any(r["state"] != "component_fix_verified" for r in results)
                else "component_fixes_verified_runtime_unverified")
