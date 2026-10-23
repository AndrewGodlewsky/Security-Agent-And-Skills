"""Component applicability, with runtime exposure left to evidence-based skills."""
from datetime import datetime, timezone
from .advisory import query_osv, validate_advisory
from .common import canonical_name, digest, now
from .versions import match_version


def fresh(timestamp, max_age_hours=24):
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - moment).total_seconds()
        return 0 <= age <= max_age_hours * 3600
    except (ValueError, TypeError, AttributeError):
        return False


def assess(advisory, inventory, online=False, max_age_hours=24):
    validate_advisory(advisory)
    if inventory.get("schema_version") != 1:
        raise ValueError("Unsupported inventory schema")
    findings, missing = [], []
    ids = {advisory["id"], *advisory.get("aliases", [])}
    query_cache = {}
    for index, target in enumerate(advisory["targets"]):
        names = {canonical_name(target["ecosystem"], n)
                 for n in [target["name"], *target.get("match_names", [])]}
        candidates = [c for c in inventory.get("components", [])
                      if c["ecosystem"] == target["ecosystem"]
                      and canonical_name(c["ecosystem"], c["name"]) in names]
        if not candidates:
            missing.append(dict(target=index, ecosystem=target["ecosystem"], name=target["name"],
                                status="unknown", reason="No matching observation in collected scope; absence is not complete inventory proof"))
        for item in candidates:
            observed = item.get("observed_at") or inventory.get("collected_at")
            try:
                status, reason = match_version(item.get("version"), target)
            except (ValueError, TypeError):
                status, reason = "unknown", "Version format cannot be evaluated by this matcher"
            if (online and advisory.get("provider") == "OSV" and item.get("version")
                    and item["evidence_kind"] in ("resolved", "installed")
                    and advisory.get("source_status") == "verified" and not advisory.get("withdrawn")):
                key = item["ecosystem"], item["name"], item["version"]
                if key not in query_cache:
                    try:
                        result = query_osv(*key)
                        matched = any(ids & {r.get("id"), *r.get("aliases", [])} for r in result)
                        query_cache[key] = ("affected" if matched else "not_affected",
                                            "OSV exact package/version query " + ("matched this advisory/alias" if matched else "did not return this advisory/alias"))
                    except Exception as exc:
                        query_cache[key] = ("unknown", "OSV query failed: " + type(exc).__name__)
                status, reason = query_cache[key]
            version_status = status
            if advisory.get("source_status") != "verified" or advisory.get("withdrawn"):
                status, reason = "unknown", "Advisory unverified or withdrawn; resolve primary-source status"
            elif not fresh(observed, max_age_hours):
                status, reason = "unknown", "Inventory timestamp missing, stale, or in the future; recollect"
            elif item["evidence_kind"] == "declared":
                status, reason = "unknown", "Declaration is not resolved/installed evidence. Version-rule result: " + version_status
            elif item.get("provenance") == "unconfirmed":
                status, reason = "unknown", "Package registry/source identity is unconfirmed; public-name matching alone is insufficient"
            prefix = target.get("version_prefix")
            if prefix and not (item.get("version") or "").startswith(prefix):
                status, reason = "unknown", "Vendor build branch does not match this rule; select a sourced branch-specific target"
            findings.append(dict(
                asset_key=item["asset_key"], target=index, ecosystem=item["ecosystem"],
                name=item["name"], version=item.get("version"), source=item["source"],
                location=item.get("location", item["source"]), scope=item.get("scope"),
                evidence_kind=item["evidence_kind"], observed_at=observed,
                applicability=status, version_status=version_status, reason=reason,
                exposure="unknown", exposure_evidence=[],
                prerequisites=target.get("prerequisites", []),
                direct=item.get("direct"), dependency_path=item.get("dependency_path"),
                fixed_versions=target.get("fixed_versions", []),
                remediation_steps=target.get("remediation_steps", [])))
    gaps = [c for c in inventory.get("coverage", []) if c["status"] != "complete"]
    return dict(schema_version=1, assessed_at=now(), advisory_id=advisory["id"],
                advisory_digest=digest(advisory), advisory_sources=advisory.get("sources", []),
                inventory_digest=digest(inventory), inventory_collected_at=inventory.get("collected_at"),
                scopes=inventory.get("scopes", []), findings=findings, missing_targets=missing,
                coverage=inventory.get("coverage", []), gaps=gaps,
                summary=dict(affected=sum(f["applicability"] == "affected" for f in findings),
                             unknown=sum(f["applicability"] == "unknown" for f in findings),
                             not_affected=sum(f["applicability"] == "not_affected" for f in findings),
                             scope_conclusion="needs_follow_up" if gaps or missing or not findings
                             or any(f["applicability"] == "unknown" for f in findings)
                             else "component_assessment_complete",
                             runtime_exposure="not_automatically_assessed"))
