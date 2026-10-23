# Case artifacts and evidence contract

Use Python 3.11+ for scripts/vuln.py and Windows PowerShell 5.1+ or PowerShell 7 for the host collector. Run helper --help for syntax. All paths should be absolute when called from another repository. Helpers use only the standard library.

A case contains the original report, advisory.json, Windows/repository inventory, assessment.json, draft plan/report, and agent-authored report.json. Verification writes new inventory/assessment files and a verification artifact. Outputs are local files, not uploads. The optional OSV request transmits identifiers or candidate package/version metadata.

## Advisory (schema_version: 1)

Required: id, targets (list), source_status (verified/unverified), sources (URL plus retrieved_at timestamp). A local unresolved identifier is allowed. sources describes provenance; “verified” means the agent checked it, not that the software is certified safe.

Each target:
- ecosystem and exact name; optional match_names for vendor-confirmed Windows/product aliases.
- version_scheme: semver, numeric, exact, or osv.
- affected_versions: explicit affected versions. Non-membership is unknown unless versions_complete is true and the source actually states an exhaustive list.
- affected_ranges: union of objects with introduced (inclusive, "0" means beginning), fixed (exclusive), or last_affected (inclusive). fixed and last_affected cannot coexist in one interval. Only semver/numeric are supported here.
- fixed_versions: advisory-listed fixes; not an instruction to select the numerically highest or lowest branch.
- version_prefix: optional vendor branch guard, such as "10.0.22631."; a mismatch is unknown pending the correct rule.
- prerequisites: sourced platform/configuration/reachability conditions.
- remediation_steps: vendor-reviewed steps for this target. The agent must specialize them to the actual location.

An OSV import retains ranges and references. Offline evaluation understands SEMVER; other ecosystem/Git ranges require exact OSV queries or a suitable ecosystem evaluator. An affected explicit version remains positive evidence. Withdrawn or unverified advisories remain inconclusive.

A vendor template can be created with intake --reported. Supply sourced rules; do not invent a schema-compatible version range merely to get a verdict. Empty targets and unresolved versions are valid incomplete work.

## Inventory

schema_version, collected_at (UTC ISO timestamp), scopes, components, coverage.

Components carry asset_key, ecosystem/name/version, source and location, scope, and evidence_kind:
- declared: requested dependency, not proof of resolution/install.
- resolved: a lockfile/build-resolution record, not proof of running code.
- installed: registry/distribution metadata.
- os: Windows build/revision.
- running: reserved for separately documented process/artifact evidence.

asset_key identifies a location independently of version, enabling before/after comparison. Retain observations separately when the same package has multiple versions or occurs in multiple projects.

Coverage status: complete, partial, unsupported, error, not_selected. A complete parser means it read that metadata, not that it inspected every installed/running copy. Default traversal skips build outputs, dependency directories and symlinks/junctions; explicitly selected Python environments are a separate collector. Inspection is capped and capped runs are partial.

## Assessment and final report

The helper emits per-observation applicability affected/not_affected/unknown and the matching reason. Missing targets stay unknown. Its runtime exposure stays unknown. Default freshness is 24 hours, configurable for a deliberate historical assessment; verification still requires fresh after-evidence.

Agent-authored report.json:
- schema_version: 1; advisory_id; generated_at; scopes.
- findings: each references asset_key/target, applicability and evidence, exposure and evidence, prerequisites checked/unresolved, prioritized actions, verification criteria, and resolution state.
- coverage_gaps; sources; overall_summary.

Exposure: demonstrated, prerequisites_present, prerequisites_absent, unknown. Each non-unknown value needs artifact/file/command evidence and observed time; “demonstrated” additionally needs actual observed reproduction authorized for that environment.

Each action records location, owner, source URL, target release/patch/configuration, ordered steps, any shell commands as text, restart/rebuild/deploy requirements, compatibility considerations, and expected verification observation. Missing fixed versions remain unresolved; never silently substitute “latest.”

The helper report is a draft. Agent refinements must preserve original observations and explain added reasoning. Severity does not replace evidence or confidence.

## Verification

Matching advisory digest and scope plus a newer observation are required for automatic comparison. A gone record is unknown, not proof of removal. A changed advisory requires reevaluation of both inventories.

component_fix_verified means the specific metadata observation now falls outside the affected rules. It does not certify running processes, deployments, or every copy. The agent may conclude verified only after all relevant component and runtime checks, or mitigated with an explicit remaining affected version and verified mitigation.
