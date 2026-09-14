# Gatekeeper

[![CI](https://github.com/samuelbacaro/gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelbacaro/gatekeeper/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)

**Gatekeeper is a free, open-source alternative to Aikido Security and other
commercial AppSec platforms.** One command runs the best open-source scanners,
merges their findings into a single risk-scored report, and generates an
AI-executable remediation plan that coding agents (Cursor, Claude Code, Copilot
Workspace) can apply directly - then verifies the fixes.

No account. No telemetry. No per-seat pricing. Runs 100% locally.

## Why Gatekeeper?

Commercial platforms charge per developer per month to orchestrate the same
open-source scanners underneath. Gatekeeper gives you that orchestration plus
the workflow around it - triage, risk scoring, AI remediation, verification -
as a tool you own:

| Capability | Gatekeeper | Aikido & co. |
|---|---|---|
| SAST + SCA + secrets + IaC + DAST in one report | Yes | Yes |
| Risk scoring (0-100), CVSS/CWE/OWASP mapping | Yes | Yes |
| Triage: ignore, accept risk, snooze, severity override | Yes | Yes |
| AI-executable fix plans / autofix | Yes (any coding agent) | Proprietary |
| Create GitHub Issue / draft fix PR per finding | Yes | Yes |
| SBOM (CycloneDX) on every scan | Yes | Paid tier |
| Price | Free, MIT | Per-seat SaaS |

## Scanners used

| Tool | Purpose |
|---|---|
| [Semgrep](https://semgrep.dev) | SAST with Gatekeeper's custom security rules (secrets, injection, crypto, web) |
| [Trivy](https://trivy.dev) | Dependency CVEs, IaC misconfigurations, secrets, containers |
| [Gitleaks](https://gitleaks.io) | Secrets committed to git history and working tree |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Vulnerability DB (OSV) coverage for dependencies |
| [Checkov](https://www.checkov.io) | IaC misconfigurations (Terraform, CloudFormation, Kubernetes, Dockerfile, CI) |
| [Syft](https://github.com/anchore/syft) | SBOM generation (CycloneDX) - saved to `raw/syft-sbom.json` |
| [Grype](https://github.com/anchore/grype) | Vulnerability scan of the Syft SBOM |
| [GuardDog](https://github.com/DataDog/guarddog) (optional) | Detects malicious PyPI/npm packages in your manifests |
| [OWASP ZAP](https://www.zaproxy.org) (optional, via Docker) | DAST against a live URL |
| [Nuclei](https://github.com/projectdiscovery/nuclei) (optional) | Template-based DAST, complements ZAP |
| [MobSF](https://mobsf.github.io) (optional, via Docker) | Deep iOS/Android static analysis via REST API |

Tools are auto-selected based on the detected stack, or forced with `--tools`.

## Install

```bash
# macOS / Homebrew
git clone https://github.com/samuelbacaro/gatekeeper.git
cd gatekeeper
./install.sh        # installs missing scanners via brew, validates the set
```

<details>
<summary>Manual installation</summary>

```bash
brew install semgrep trivy gitleaks osv-scanner checkov syft grype nuclei
pip3 install guarddog   # optional: malicious package detection
```

Docker is only needed for the optional `--dast` (ZAP) and MobSF mobile scans.
</details>

## Usage

```bash
# Full scan of a local project
./bin/gatekeeper scan /path/to/project

# Scan and also run a DAST scan against a live site
./bin/gatekeeper scan /path/to/project --dast https://example.com

# Restrict to specific tools
./bin/gatekeeper scan /path/to/project --tools semgrep,gitleaks

# Verify fixes made since the last scan (exit code 1 if HIGH/CRITICAL remain)
./bin/gatekeeper verify /path/to/project
```

### Try it on the vulnerable demo app

```bash
./bin/gatekeeper scan ./sample-vulnerable-app
```

## Web UI

```bash
./bin/gatekeeper-ui
```

Opens a local dashboard at `http://127.0.0.1:8695` (localhost only, stdlib only):

- **New Scan** button with a native macOS folder picker
- Live per-tool progress while scanning
- Severity cards, charts by category/tool, filterable findings table ranked by
  risk score, with inline code snippets, CVSS/CWE/OWASP metadata
- Per-issue actions: AutoFix prompt, Solved, Ignore (with reason + risk
  acceptance), severity override, **GitHub Issue** and **Fix PR** buttons
- **AI Plan** tab with one-click "Copy AI Plan" and "Download .md" - paste it
  into Cursor and ask the agent to execute the directives
- Scan history sidebar (loads previous scans from `reports/`)

## Outputs (in `reports/<timestamp>/`)

| File | Purpose |
|---|---|
| `REPORT.md` / `REPORT.html` | Human-readable findings report |
| `REMEDIATION_PLAN.md` | Prioritized fix plan with **AI directives** — point the Cursor agent at this file |
| `summary.json` | Machine-readable unified findings (CVSS, CWE/OWASP, risk score, code snippets) |
| `raw/` | Raw JSON output of each scanner, plus the CycloneDX SBOM |

## Using with Cursor (or any coding agent)

1. Run `./bin/gatekeeper scan /path/to/project`.
2. Ask the Cursor agent: *"Read reports/REMEDIATION_PLAN.md and execute all
   directives for this project."*
3. When the agent finishes, ask it to run
   `./bin/gatekeeper verify /path/to/project` — it exits 0 only when no
   HIGH/CRITICAL findings remain, so the agent can loop until the codebase is
   clean.

## CI gate

`gatekeeper verify` is designed to be used as a pipeline gate:

```yaml
# .github/workflows/security.yml
- name: Gatekeeper verify
  run: gatekeeper verify . # exits 1 if HIGH/CRITICAL findings remain
```

## Project layout

```
bin/                       Executable entry points (gatekeeper, gatekeeper-ui)
gatekeeper/
  core/                    Scan pipeline, CLI, reporting, triage, GitHub integration
  scanners/                Per-tool scanner runners
  ui/                      Local web dashboard (stdlib HTTP server + static HTML)
  rules/                   Custom Semgrep rules shipped with Gatekeeper
docs/                      Documentation
sample-vulnerable-app/     Intentionally vulnerable demo app for testing scans
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No HIGH/CRITICAL findings |
| 1 | HIGH/CRITICAL findings present |
| 2 | Usage or runtime error |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests are
welcome via [Issues](https://github.com/samuelbacaro/gatekeeper/issues).

## Security

Found a vulnerability in Gatekeeper itself? See
[SECURITY.md](SECURITY.md) - please do not open a public issue.

## License

[MIT](LICENSE)
