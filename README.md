# Gatekeeper

[![CI](https://github.com/sbacaro/gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/sbacaro/gatekeeper/actions/workflows/ci.yml)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm--NC-orange.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)

**Gatekeeper is a free alternative to commercial AppSec platforms.** One command runs the best open-source scanners, merges
their findings into a single risk-scored report, and generates an
AI-executable remediation plan that coding agents (Cursor, Claude Code, Copilot
Workspace) can apply directly - then verifies the fixes.

No account. No telemetry. No per-seat pricing. Runs 100% locally.

## Why Gatekeeper?

Commercial platforms charge per developer per month to orchestrate the same
open-source scanners underneath. Gatekeeper gives you that orchestration plus
the workflow around it - triage, risk scoring, AI remediation, verification -
as a tool you own:

| Capability | Gatekeeper | The $30/dev/month platforms |
|---|---|---|
| SAST + SCA + secrets + IaC + DAST in one report | Yes | Yes |
| Risk scoring (0-100), CVSS/CWE/OWASP mapping | Yes | Yes |
| **CISA KEV + EPSS threat intel on every CVE** | Yes (offline cache) | Yes |
| Secret validity checks (is the credential still live?) | Yes (opt-in) | Paid tier |
| Triage: ignore, accept risk, snooze, severity override | Yes | Yes |
| AI-executable fix plans / autofix | Yes (any coding agent) | Proprietary |
| **MCP server** - agents operate Gatekeeper natively | Yes | No |
| Closed-loop dependency autofix (`fix` -> verify -> PR) | Yes | Paid tier |
| SARIF export + diff-aware PR gate (`ci`) | Yes | Yes |
| Create GitHub Issue / draft fix PR per finding | Yes | Yes |
| SBOM (CycloneDX) on every scan | Yes | Paid tier |
| Price | Free for noncommercial use | Per-seat SaaS |

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

Gatekeeper runs on **macOS, Linux and Windows** (Python 3.9+ required; the
scanners are the platform-specific part).

### macOS

```bash
git clone https://github.com/sbacaro/gatekeeper.git
cd gatekeeper
./install.sh        # installs missing scanners via Homebrew, validates the set
```

### Linux

```bash
git clone https://github.com/sbacaro/gatekeeper.git
cd gatekeeper
./install.sh        # detects your distro and prints per-tool instructions
```

Or install manually:

```bash
pip3 install semgrep checkov
# trivy, gitleaks, osv-scanner, syft, grype, nuclei: use your package manager
# or the official install scripts (./install.sh prints the exact commands).
```

For the web UI folder picker on Linux, install a picker backend:
`sudo apt install zenity` (GNOME/any DE) or `kdialog` (KDE), or
`sudo apt install python3-tk` for the tkinter fallback.

### Windows

```powershell
git clone https://github.com/sbacaro/gatekeeper.git
cd gatekeeper
pip install semgrep checkov
# trivy:    choco install trivy   |  scoop install trivy
# gitleaks: choco install gitleaks |  scoop install gitleaks
# osv-scanner, syft, grype, nuclei: download from their GitHub releases

python bin\gatekeeper scan C:\path\to\project
python bin\gatekeeper-ui
```

<details>
<summary>macOS one-liner (manual)</summary>

```bash
brew install semgrep trivy gitleaks osv-scanner checkov syft grype nuclei
pip3 install guarddog   # optional: malicious package detection
```
</details>

Docker is only needed for the optional `--dast` (ZAP) and MobSF mobile scans.

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

### Validate leaked credentials (opt-in)

```bash
# Checks each found secret against its provider API (GitHub, Slack, Stripe,
# OpenAI, Google, npm). A confirmed-live credential is promoted to CRITICAL
# and flagged as [CREDENTIAL CONFIRMED LIVE]. Generates provider audit-log
# events, so it is opt-in.
./bin/gatekeeper scan ./sample-vulnerable-app --validate-secrets
```

### Diff-aware CI gate for pull requests

`gatekeeper ci` scans, keeps only findings introduced by the change (line
drift is tolerated via stable fingerprints) and emits SARIF for GitHub Code
Scanning. Pre-existing findings do not block the PR - that is `verify`'s job.

```yaml
# .github/workflows/security.yml
- name: Gatekeeper PR gate
  run: |
    gatekeeper ci . --base origin/main --sarif-out gatekeeper.sarif
    gh api repos/$REPO/code-scanning/sarifs -f sarif=@gatekeeper.sarif || true
```

### Closed-loop dependency autofix

`gatekeeper fix` bumps vulnerable dependencies (npm/pnpm/yarn/requirements.txt),
re-scans to confirm the CVEs are gone, and opens a draft PR via `gh`:

```bash
./bin/gatekeeper fix ./sample-vulnerable-app          # bumps + verify + PR
./bin/gatekeeper fix ./sample-vulnerable-app --no-pr  # local bumps only
```

### Policy as code (`gatekeeper.yml`)

Drop a `gatekeeper.yml` in the repository root (see
[gatekeeper.example.yml](gatekeeper.example.yml)) to version your security
policy next to the code. Every command - `scan`, `verify`, `ci` - reads it:

```yaml
fail_on: high                # exit 1 when findings >= HIGH (or: critical|medium|low)
min_risk_score: 80           # ...or when any finding scores >= 80
tools: [semgrep, trivy, gitleaks]
ignore_paths:
  - tests/fixtures/
ignore:
  - title: "Hardcoded JWT secret"        # exact title, with audit reason
    reason: "test fixture, not a real credential"
notifications:
  slack: https://hooks.slack.com/services/...   # Slack + generic webhooks
  webhook: https://ci.example.com/hook
  min_severity: high
```

CLI flags override the file (`--tools`, `--validate-secrets`), and
`--config path/to/gatekeeper.yml` points at an explicit policy file.

### MCP server for coding agents

Gatekeeper ships a built-in MCP (Model Context Protocol) server, so agents
like Cursor can *operate* Gatekeeper natively instead of reading a plan file:

```json
// .cursor/mcp.json (or your MCP client's config)
{
  "mcpServers": {
    "gatekeeper": { "command": "/path/to/gatekeeper/bin/gatekeeper", "args": ["mcp"] }
  }
}
```

Tools exposed: `gatekeeper_scan`, `gatekeeper_list`, `gatekeeper_finding`,
`gatekeeper_triage`, `gatekeeper_verify`, `gatekeeper_plan`, `gatekeeper_fix`,
`gatekeeper_ci`, `gatekeeper_sarif`, `gatekeeper_policy`.

### SARIF output

Every scan writes `gatekeeper.sarif` alongside the other reports; you can also
convert or re-print the latest scan:

```bash
gatekeeper sarif /path/to/project > results.sarif
```

## Web UI

```bash
./bin/gatekeeper-ui
```

Opens a local dashboard at `http://127.0.0.1:8695` (localhost only, stdlib only):

- **New Scan** button with a native folder picker (NSOpenPanel on macOS,
  FolderBrowserDialog on Windows, zenity/kdialog on Linux)
- **Re-scan** button to repeat the last scan on the same repository at any time
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
| `summary.json` | Machine-readable unified findings (CVSS, CWE/OWASP, risk score, KEV/EPSS, code snippets) |
| `gatekeeper.sarif` | SARIF 2.1.0 export for GitHub Code Scanning / IDEs |
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
  mcp/                     MCP server for coding agents (stdio, zero deps)
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

## Threat intelligence (KEV + EPSS)

Every SCA finding is enriched with two free public feeds, cached locally
(`~/.cache/gatekeeper/`, 24h TTL) so scans stay fully offline after the first
refresh:

- **CISA KEV** - the CVE is exploited in the wild (adds up to +30 risk points;
  ransomware-linked CVEs get extra weight)
- **EPSS** - probability of exploitation in the next 30 days (up to +15)

A KEV-listed CRITICAL CVE tops the report at risk 100. Findings without any
intel fall back to keyword-based exploitability heuristics.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests are
welcome via [Issues](https://github.com/sbacaro/gatekeeper/issues).

### Development

```bash
pip install pytest
python -m pytest tests/ -v   # unit tests (no scanners required)
ruff check gatekeeper/ bin/ tests/
```

The test suite is pure-unit: scanner runs, subprocesses and network calls are
mocked, so it runs in well under a second without any scanner installed.

## Security

Found a vulnerability in Gatekeeper itself? See
[SECURITY.md](SECURITY.md) - please do not open a public issue.

## License

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE): you may
use, study, modify and share Gatekeeper freely for any **noncommercial**
purpose - personal projects, research, education, and use by charities,
schools and government institutions.

**Commercial use requires a separate license** from the author. If your
company wants to use Gatekeeper in a product or paid service,
[open an issue](https://github.com/sbacaro/gatekeeper/issues/new?template=feature_request.md&title=Commercial%20license%20inquiry)
to discuss it.
