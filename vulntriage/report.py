"""Remediation drafts and human reports. This module executes no commands."""
from .common import now


def build_plan(assessment):
    actions = []
    for f in assessment["findings"]:
        if f["applicability"] == "not_affected":
            continue
        steps = []
        if f["applicability"] == "unknown":
            steps.append("Resolve the evidence gap before claiming this installation is affected: " + f["reason"])
        if f.get("remediation_steps"):
            steps.extend(f["remediation_steps"])
        elif f.get("fixed_versions"):
            steps.append("Consult the cited advisory and select the compatible fixed release from: "
                         + ", ".join(f["fixed_versions"]) + ". Different release branches may require different fixes.")
            if f["ecosystem"] == "Windows":
                steps.append("Use the application's vendor updater or the applicable Microsoft update for this exact product/build; check restart requirements.")
            elif f.get("direct") is True:
                steps.append("Update the direct dependency in the owning project, regenerate its lockfile with the project's package manager, and review the resulting diff.")
            else:
                steps.append("Trace the introducing direct dependency before changing the manifest; update that dependency or use a vendor-supported override.")
        else:
            steps.append("Obtain the vendor-confirmed fixed version or mitigation; no fixed version has been established.")
        steps.append("Refresh inventory at the same location after the change. If used at runtime, rebuild/redeploy or restart as appropriate and verify the running artifact.")
        actions.append(dict(asset_key=f["asset_key"], target=f["target"], location=f["location"],
                            component=f["name"], observed_version=f["version"], state="proposed",
                            steps=steps, verification=[
                                "Repeat collection and assessment using the same advisory and scope",
                                "Confirm the affected component/version is replaced, or document removal with explicit evidence",
                                "Confirm relevant runtime prerequisites and regression checks after restart/redeploy"]))
    return dict(schema_version=1, created_at=now(), advisory_id=assessment["advisory_id"],
                advisory_digest=assessment["advisory_digest"], actions=actions,
                unresolved_targets=assessment.get("missing_targets", []),
                state="proposed", note="Agent must specialize and source these steps; nothing has been applied")


def cell(value):
    return str(value if value is not None else "unknown").replace("|", r"\|").replace("\n", " ").replace("\r", "")


def render_report(assessment, plan):
    lines = ["# Vulnerability assessment: " + cell(assessment["advisory_id"]), "",
             "Component presence and runtime exposure are separate conclusions. This report applies only to the recorded scope.",
             "", "## Observed components", "",
             "| Component | Version | Evidence | Applicability | Location |",
             "| --- | --- | --- | --- | --- |"]
    for f in assessment["findings"]:
        lines.append("| " + " | ".join(cell(f[k]) for k in ("name", "version", "evidence_kind", "applicability", "location")) + " |")
    if not assessment["findings"]:
        lines.append("| No matching observations | — | — | unknown | See coverage |")
    lines += ["", "## Evidence and exposure", ""]
    for f in assessment["findings"]:
        lines += [f"- {cell(f['name'])} at {cell(f['location'])}: {cell(f['reason'])}",
                  "  Exposure: " + cell(f["exposure"]) + ". Prerequisites: " + cell(", ".join(f["prerequisites"]) or "Require advisory-specific investigation")]
    lines += ["", "## Proposed remediation", ""]
    for action in plan["actions"]:
        lines += ["### " + cell(action["component"]) + " — " + cell(action["location"]), ""]
        lines += [f"{i}. {cell(step)}" for i, step in enumerate(action["steps"], 1)]
        lines += ["", "Verification:", ""]
        lines += ["- " + cell(step) for step in action["verification"]]
        lines.append("")
    lines += ["## Coverage and unresolved checks", ""]
    for item in assessment.get("missing_targets", []):
        lines.append("- " + cell(item["name"]) + ": " + cell(item["reason"]))
    for item in assessment["coverage"]:
        lines.append(f"- [{cell(item['status'])}] {cell(item['scope'])}: {cell(item['detail'])}")
    lines += ["", "## Advisory sources", ""]
    for source in assessment["advisory_sources"]:
        lines.append("- " + cell(source["url"]) + " (retrieved " + cell(source["retrieved_at"]) + ")")
    lines += ["", "No changes were applied by the helper. A proposed remedy is not a verified resolution.", ""]
    return "\n".join(lines)
