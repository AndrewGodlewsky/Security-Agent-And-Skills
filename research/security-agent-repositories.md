# GitHub security agents worth investigating

Researched October 23, 2026. Sources are upstream repositories, their documentation, and GitHub metadata. This is a discovery and fit assessment, not a hands-on evaluation: no software was installed and no targets were scanned. Recommendations below are judgments from documented scope; vendor benchmark claims were not used as evidence of detection quality.

The strongest starting points are **Trail of Bits skills** for security review inside an existing coding agent, **Strix** for autonomous application testing, and **Shannon** for source-assisted tests against a running web application. For the computer itself, **ai-agent-audit** is unusually relevant to developer-machine exposure, while **Wazuh** covers conventional endpoint vulnerability monitoring, including Windows. These are different kinds of “agent.”

| Repository | What it is | Best fit | Principal limitation |
| --- | --- | --- | --- |
| [usestrix/strix](https://github.com/usestrix/strix) | Autonomous AI pentesting agents | Local code, repository URLs, deployed applications | Active testing; local execution still needs a configured model |
| [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | Autonomous AI web/API pentester | Source repository plus running application | Exploit-oriented coverage; explicitly unsuitable for production tests |
| [trailofbits/skills](https://github.com/trailofbits/skills) | Security skills/plugins for an existing AI agent | Repository audits and focused review workflows | Requires an agent runtime and any underlying analysis tools |
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | Claude-powered review workflow | Pull requests and pending code changes | Upstream warns it is not hardened against prompt injection |
| [protectai/vulnhuntr](https://github.com/protectai/vulnhuntr) | Automated LLM-assisted code investigation | Python repository vulnerability discovery | Python-only, narrow vulnerability classes, older maintenance evidence |
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | Autonomous pentest framework plus interactive mode | Authorized service/network testing and security labs | Less directly suited to routine repository or endpoint health checks |
| [bartek-filipiuk/ai-agent-audit](https://github.com/bartek-filipiuk/ai-agent-audit) | Shell auditor with optional agent skill | Local developer-machine exposure to AI tools | Linux/macOS; heuristic checks rather than a general vulnerability engine |
| [wazuh/wazuh](https://github.com/wazuh/wazuh) | Conventional endpoint agent/platform | Installed-software vulnerabilities and host monitoring | Not an LLM agent; needs central infrastructure |

## Repository details

### Strix

The documented CLI accepts local source, GitHub repositories, and application targets. Agents combine code inspection, browser/terminal tools, and proof-of-concept validation. The local edition requires Docker and an LLM configuration; reports are saved locally. A separate managed service also exists. License: Apache-2.0. This is the broadest autonomous application-testing candidate in this shortlist. [Upstream README](https://github.com/usestrix/strix#readme), [target and setup examples](https://github.com/usestrix/strix/blob/main/skills/penetration-testing-with-strix/SKILL.md).

“Runs locally” describes execution, not a guarantee that code stays on the machine: the default setup calls a model provider. It is an application pentester, not a Windows patch, antivirus, or host-hardening agent. That distinction follows from the documented targets and provider setup.

### Shannon

Combines repository analysis with live browser/command-line exploitation of web applications and APIs. Setup requires Docker, Node.js 18+ for the recommended launcher, model credentials, source code, and a reachable application. The repository is mounted read-only into its worker; results remain in a local workspace. Upstream documents local-model endpoints as an option and says Keygraph does not proxy model traffic. License: AGPL-3.0. [README and setup](https://github.com/KeygraphHQ/shannon#readme).

Read-only source mounting does not make application testing read-only. Its safety documentation explicitly excludes production use because exploitation can change users or data. It focuses on exploitable authentication, authorization, injection, XSS, and SSRF findings; this does not replace broad dependency or configuration checks. [Safety and scope](https://github.com/KeygraphHQ/shannon/blob/main/docs/safety.md).

### Trail of Bits skills

A particularly relevant reference for this repository's agent-and-skills direction. It packages workflows rather than a standalone security agent. Useful entries include `differential-review`, `static-analysis` (CodeQL/Semgrep/SARIF), `insecure-defaults`, `variant-analysis`, and `supply-chain-risk-auditor`. It documents use with existing Claude Code and Codex installations. License: CC-BY-SA-4.0. [Marketplace README and license](https://github.com/trailofbits/skills#readme).

Choose the workflows relevant to the project instead of treating the whole collection as one scanner. Model access, privacy, permissions, and execution depend on the agent hosting the skills; analysis tools may need their own installation and configuration. This is an inference from its plugin architecture, not an offline-processing promise.

### Claude Code Security Review

Anthropic's GitHub Action reviews changed code in context, filters findings, and can post PR comments. It requires a Claude API key. The repository also supplies a customizable security-review command, and documents local review of pending changes. License: MIT. This is a convenient focused workflow for teams already using Claude. [Upstream README](https://github.com/anthropics/claude-code-security-review#readme).

Its explicit limitation matters: the action is not hardened against prompt injection and is intended for trusted PRs. Default filtering also excludes some categories, including denial-of-service and rate-limiting concerns. A clean report therefore does not imply complete coverage. [Security considerations and filtering](https://github.com/anthropics/claude-code-security-review#security-considerations).

### Vulnhuntr

Analyzes chains of Python calls from remote input toward sensitive behavior, using LLMs and static code analysis. It takes a local repository path and supports Claude, GPT, and Ollama clients. The README strictly requires Python 3.10 and offers Docker or pipx installation. License: AGPL-3.0. [README and license](https://github.com/protectai/vulnhuntr#readme).

Coverage is limited to Python and seven documented vulnerability classes, including RCE, SQL injection, SSRF, XSS, and IDOR. Its source examples make it useful to study, but the older visible commit history and runtime constraint make it a secondary practical choice. Cloud-model configuration transmits analysis context to that provider; Ollama support should not be interpreted as an equivalent-quality guarantee. [Usage and limitations](https://github.com/protectai/vulnhuntr/blob/main/README.md), [commit history](https://github.com/protectai/vulnhuntr/commits/main/).

### PentestGPT

The current project has autonomous staged testing using Claude Code or Codex and a separate interactive legacy mode supporting additional providers, including Ollama. Documented setup uses Python 3.12+, uv, and an authenticated backend CLI, with a Docker option. License: MIT. It is more relevant to testing reachable services or lab targets than to inspecting installed Windows software. [README](https://github.com/GreyDGL/PentestGPT#readme).

Upstream documents usage telemetry sent to Langfuse, with `--no-telemetry` or `LANGFUSE_ENABLED=false` opt-outs. This is separate from model-provider traffic. Its historical benchmark result is explicitly not a guarantee for the current runtime. [Telemetry and benchmark caveat](https://github.com/GreyDGL/PentestGPT#telemetry).

### ai-agent-audit

Fifteen Bash audit modules inspect the local developer environment: exposed credentials, AI-tool configuration, hooks, skills, MCP configuration, histories, and selected supply-chain indicators. It can run directly or through its Claude skill; the underlying auditor is deterministic shell code. Requires Bash 4.4+ and targets Linux/macOS, not native Windows host coverage. License: MIT. [README](https://github.com/bartek-filipiuk/ai-agent-audit#readme).

The audit path is documented as read-only outside its output directory and produces redacted reports. There is a separate opt-in purge script. It is not network-free: authenticated `gh`/`npm` calls and potentially `op whoami` contact services. Pattern checks can produce false positives, and the compromised-package list is a static snapshot. Useful inspiration for an agent-aware workstation checklist; not evidence that a machine is fully secure. [Guarantees and limitations](https://github.com/bartek-filipiuk/ai-agent-audit/blob/main/README.md).

### Wazuh

For actual computer vulnerability monitoring, including Windows, this is the relevant conventional-agent comparison. Agents inventory installed software on Windows, Linux, and macOS; central components correlate it against vulnerability information. It requires a server/indexer/dashboard deployment rather than only a local chat session. Its core vulnerability mechanism is inventory/feed correlation, not autonomous LLM reasoning. [Vulnerability detection documentation](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html).

The current main branch has component-specific GPL/AGPL licensing; inspect the selected release's license before reuse. Do not assume the development branch describes the stable version you will deploy. [Repository license explanation](https://github.com/wazuh/wazuh#authors).

## Maintenance evidence and exclusions

Activity is a signal, not a quality or safety certification. Some web responses were cached; dates below distinguish observed history from a claim about the latest commit.

- **Strix:** GitHub API reported an unarchived repository and a push on October 23, 2026 UTC. [Metadata](https://api.github.com/repos/usestrix/strix).
- **Shannon:** GitHub API reported an unarchived repository and a push on October 15, 2026 UTC. [Metadata](https://api.github.com/repos/KeygraphHQ/shannon).
- **Trail of Bits:** retrieved history includes September 2026 maintenance and August workflow changes. [History](https://github.com/trailofbits/skills/commits/main/).
- **PentestGPT:** retrieved history includes a July 2026 runtime update. [History](https://github.com/GreyDGL/PentestGPT/commits/main/).
- **Claude review:** retrieved history's newest visible entry was February 11, 2026. **Vulnhuntr:** February 6, 2025. Treat these as older activity evidence, not independently verified present-day inactivity. [Claude history](https://github.com/anthropics/claude-code-security-review/commits/main/), [Vulnhuntr history](https://github.com/protectai/vulnhuntr/commits/main/).
- **ai-agent-audit:** a small project worth inspecting, without an independently verified maintenance cadence in this research. **Wazuh:** ongoing upstream releases are visible. [Audit repository](https://github.com/bartek-filipiuk/ai-agent-audit), [Wazuh releases](https://github.com/wazuh/wazuh/releases).
- **[aliasrobotics/cai](https://github.com/aliasrobotics/cai)** is relevant historically but excluded from the adoption shortlist: GitHub marks it archived on August 28, 2026, and its README states that development, fixes, and support have ended. Study its architecture if useful; do not select it expecting a maintained open-source security agent.

## Suggested evaluation order

1. **Existing coding-agent workflow:** inspect Trail of Bits skills first; add Claude Security Review if PR automation is the main requirement.
2. **Autonomous testing of your own application:** compare Strix and Shannon on the same disposable local/staging project and manually reproduce their findings.
3. **Python-specific research:** examine Vulnhuntr as a focused reference with maintenance/runtime limitations.
4. **Developer-machine exposure:** examine ai-agent-audit for Linux/macOS; for Windows installed-software vulnerabilities and continuing monitoring, evaluate Wazuh separately.

Local execution, local-model inference, and local-machine coverage are three distinct properties. None of the application-testing agents above should be assumed to provide a complete endpoint security check merely because its CLI runs on your computer.
