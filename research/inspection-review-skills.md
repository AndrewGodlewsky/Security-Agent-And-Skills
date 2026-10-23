# Source inspection: repository assessment and security skills

Inspected on October 23, 2026. Objective: given a reported vulnerability, identify affected software on a computer or in repositories, distinguish actual exposure from incomplete evidence, and produce actionable remediation with verification. This is source inspection, not execution or a security audit of these tools. No dependencies were installed and no upstream code was run. The clones are under `research/upstream/`.

## Recommendation

Trail of Bits is the strongest direct source of reusable components among these three. Its current supply-chain collector already performs exact-version advisory checks and preserves incomplete coverage. Combine those mechanisms with its variant-analysis evidence questions and post-patch validation contract. Claude Code Security Review is useful mainly for report formatting and a second review pass; its default scope and exclusion policy conflict with this objective. Vulnhuntr supplies a useful iterative source-context retrieval pattern, but is a Python application vulnerability discovery tool rather than a known-advisory exposure checker.

These are design recommendations inferred from the inspected implementations. None of these three provides a complete Windows software inventory, running-process-to-package mapping, advisory ingestion, host exposure analysis, and verified remediation workflow.

## Trail of Bits skills

- Upstream: https://github.com/trailofbits/skills
- Inspected HEAD: `196a9073ab10d35bacf111f945e02c00b2c6883a`
- Root license: CC BY-SA 4.0, as stated in [LICENSE](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/LICENSE#L1). Preserve attribution and assess share-alike requirements before incorporating material. No separate license was found in the examined supply-chain and post-patch plugin directories.

### Components worth adapting

**Dependency identity and advisory matching.** `supply-chain-risk-auditor` separates deterministic collection from the agent's judgment. The OSV client submits ecosystem/name/version tuples in batches of up to 500, preserves separate results for multiple versions of a package, and rejects response-cardinality mismatches instead of shifting results to the wrong dependency. See [sources.py:275](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/scripts/sources.py#L275). This is directly reusable for “is the reported package/version present?”

**Transitive coverage with an explicit ledger.** The collector checks public-registry-attested packages from npm lockfiles, `uv.lock`, and Go module information, including dependencies beyond the direct set. Unverifiable entries and OSV failures remain visible. The implementation retains ecosystem, package, version, development status and advisory IDs; it does not silently treat unqueried entries as clean. See [collect.py:1187](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/scripts/collect.py#L1187) and [ledger reconciliation in model.py:321](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/scripts/model.py#L321).

**Evidence-bearing negative results.** `Signal` uses `assessed_clean`, `assessed_flagged`, and `unassessable`; even a clean result must include a measured datum, and unassessable requires a reason. Coverage reconciliation catches dropped entries, zero-dependency reports, and reports with no meaningful measurement. See [model.py:22](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/scripts/model.py#L22) and [model.py:229](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/scripts/model.py#L229). This is the most valuable pattern for avoiding a false “your computer is safe” conclusion.

**Known-pattern investigation.** `variant-analysis` starts from an already-known defect, confirms an exact match, then generalizes one search dimension at a time. Its triage reference checks entry-point reachability, attacker control, and intervening protection, and records ruled-out candidates with reasons. See [SKILL.md:29](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/variant-analysis/skills/variant-analysis/SKILL.md#L29) and [triage.md:7](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/variant-analysis/skills/variant-analysis/references/triage.md#L7). Adapt this after identifying an affected component, particularly for vendored code or backported patches. Its policy calls unreachable-but-unprotected code a lower-severity finding; our report should separately label component presence and current exposure so that distinction stays clear.

**Remediation verification.** `post-patch-validation` pins vulnerable and patched inputs and separates source, build, and runtime evidence. Its runner checks reproduction, variants, benign controls, preserved behavior, regressions, neighboring security behavior, and the existing suite. Missing execution markers and failed baseline controls become gaps, not evidence of a successful fix. See [evidence contract](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/post-patch-validation/skills/post-patch-validation/SKILL.md#L86) and [implemented assessment logic](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/post-patch-validation/skills/post-patch-validation/scripts/post_patch_validation.py#L1183). Borrow the before/after evidence model; the complete seven-kind validation workflow may be excessive for routine package upgrades.

### Gaps for this project

The collector supports npm, PyPI and Go, and explicitly does not read Yarn, pnpm or Poetry lockfiles. With unresolved version ranges it may check the latest release; that result cannot establish the locally installed version's status. It reads metadata rather than application/dependency source and cannot establish reachability. See [supported inputs and fallbacks](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/SKILL.md#L31) and [version notes](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/scripts/collect.py#L1392).

The OSV client returns advisory IDs, not complete fixed-version and exploit-prerequisite records. The skill delegates upgrade-path analysis to the agent ([workflow step 5](https://github.com/trailofbits/skills/blob/196a9073ab10d35bacf111f945e02c00b2c6883a/plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/SKILL.md#L54)). Add an advisory-normalization layer for CVE/GHSA/OSV aliases, affected ranges, vendor backports, fixes and mitigation prerequisites. Querying metadata endpoints also discloses package identities; the collector is read-only with respect to target code, not an offline-only analysis.

## Anthropic Claude Code Security Review

- Upstream: https://github.com/anthropics/claude-code-security-review
- Inspected HEAD: `0c6a49f1fa56a1d472575da86a94dbc1edb78eda`
- Root license: [MIT, copyright Anthropic](https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/LICENSE#L1).

**Useful:** the audit prompt asks for repository security context, caller/dataflow investigation, exploitation scenarios, concrete recommendations, severity and confidence in structured JSON. These fields make a useful starting report schema. See [prompts.py:103](https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/claudecode/prompts.py#L103). Its filter records excluded findings and reasons alongside kept findings, useful for review traceability ([findings_filter.py:205](https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/claudecode/findings_filter.py#L205)).

**Important mismatch:** the prompt limits review to vulnerabilities newly introduced by a PR and explicitly excludes existing concerns, DOS and selected other classes. The code hard-excludes matches for DOS, open redirects, regex injection, resource management and some memory-safety reports. A reported advisory may be exactly one of these categories. Do not reuse this suppression policy for an exposure triage agent. See [scope and exclusions](https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/claudecode/prompts.py#L49) and [hard exclusions](https://github.com/anthropics/claude-code-security-review/blob/0c6a49f1fa56a1d472575da86a94dbc1edb78eda/claudecode/findings_filter.py#L90).

The inspected audit/filter pathway does not provide installed-package inventory, deterministic advisory range matching, a host exposure model, or a remediation verification contract. Its confidence score is model judgment, not proof that the vulnerable behavior executed. Best use: optional review of a remediation PR after the core exposure workflow has reached a conclusion.

## Protect AI Vulnhuntr

- Upstream: https://github.com/protectai/vulnhuntr
- Inspected HEAD: `ead88c5adba4279dae5c56d65124c530a9a1c5ae`
- Root license: [GNU AGPL v3](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/LICENSE#L1). Prefer learning from the retrieval pattern over casually copying code into differently licensed software.

**Useful:** after initial analysis it iteratively asks for missing function/class definitions and incorporates those definitions into vulnerability-specific analysis, up to seven iterations. A Jedi-based symbol extractor searches files and the project to locate actual definitions. See [analysis loop](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/vulnhuntr/__main__.py#L401) and [symbol_finder.py:13](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/vulnhuntr/symbol_finder.py#L13). This suggests a narrowly scoped “follow the caller until the exposure prerequisite is resolved” subroutine.

**Gaps:** normal operation starts from regex-selected Python network-entry files; it excludes tests, examples, virtual environments and installed package directories. The CLI accepts a repository/path and LLM selection, not an advisory or affected-version specification. See [file selection](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/vulnhuntr/__main__.py#L92) and [CLI/control flow](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/vulnhuntr/__main__.py#L320).

The response schema provides analysis, PoC, confidence and requested context, but no structured fixed version or remediation verification record ([schema](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/vulnhuntr/__main__.py#L47)). Its prompts explicitly tell the model not to request standard-library or third-party package source and to rely on what it knows instead ([prompts.py:330](https://github.com/protectai/vulnhuntr/blob/ead88c5adba4279dae5c56d65124c530a9a1c5ae/vulnhuntr/prompts.py#L330)). That is especially unsuitable for newly disclosed dependency vulnerabilities. The iteration stops when context stops growing; this should become “analysis incomplete” if prerequisites remain unresolved, not a clean verdict.

## Proposed adaptation order

1. Adopt the Trail of Bits evidence states, coverage accounting and package/version identity model.
2. Add advisory ingestion and normalize aliases, affected versions, conditions, vendor fixes and mitigations.
3. Gather separate observed inventories for repository resolution, actual runtime environments, and host-installed products. Never substitute latest-release metadata for an observed installation.
4. Use focused caller/configuration analysis to determine exposure, borrowing variant-analysis questions and Vulnhuntr's retrieval loop.
5. Produce per-location actions: exact target version or configuration change, the package manager/application responsible, restart/rebuild/redeploy requirements, and a check that proves the change took effect.
6. Preserve unknowns and a before/after evidence record. Use deeper post-patch validation for source fixes when execution is authorized; routine upgrades need inventory refresh and relevant regression checks.

No implementation or upstream integration was performed as part of this inspection.
