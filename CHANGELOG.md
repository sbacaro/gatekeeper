# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-09-14

### Added
- Repository policy file (`gatekeeper.yml`): per-repo tool selection, secret
  validation toggle and notification settings, loaded automatically from the
  scanned project or via `--config`. See `gatekeeper.example.yml`.
- Notifications on `gatekeeper verify`: webhook (Slack-compatible) and
  generic HTTP endpoint, configured in `gatekeeper.yml`.
- MCP server expansion: `gatekeeper_plan`, `gatekeeper_verify` and diff-aware
  triage tools for coding agents.
- Unit test suite (128 tests, no scanners required) wired into CI across
  Python 3.9/3.12/3.13.
- UI: centered main content, topbar action buttons pinned right, blue design
  system, footer with version from the API.

### Changed
- Documentation no longer references specific commercial product names.

## [1.1.0] - 2026-09-14

### Added
- Threat intelligence enrichment (CISA KEV + FIRST EPSS) with a 24h local
  cache; KEV-listed CVEs are boosted to the top of the risk ranking.
- SARIF 2.1.0 export (`gatekeeper.sarif` per scan + `gatekeeper sarif` CLI)
  for GitHub Code Scanning and IDE integrations.
- `gatekeeper ci`: diff-aware PR gate that keeps only findings introduced by
  the change (fingerprint-based identity tolerates line drift) and emits SARIF.
- `gatekeeper fix`: closed-loop SCA autofix - bumps vulnerable dependencies
  (npm/pnpm/yarn/requirements.txt), re-scans to verify and opens a draft PR.
- Built-in MCP server (`gatekeeper mcp`): coding agents operate Gatekeeper
  natively via `gatekeeper_scan`, `gatekeeper_list`, `gatekeeper_finding`,
  `gatekeeper_triage`, `gatekeeper_verify` and `gatekeeper_plan`.
- Secret validity checks (`scan --validate-secrets`): probes leaked
  credentials against their provider APIs; a confirmed-live credential is
  promoted to CRITICAL with a `[CREDENTIAL CONFIRMED LIVE]` flag.

## [1.0.0] - 2026-09-14

### Added
- Unified scan pipeline orchestrating Semgrep, Trivy, Gitleaks, OSV-Scanner,
  Checkov, Syft, Grype (plus optional GuardDog, ZAP, Nuclei and MobSF).
- Risk scoring (0-100) combining severity, CVSS and exploitability signals.
- CVSS / CWE / OWASP Top 10 2021 mapping for every finding.
- Code snippets embedded in reports, UI and remediation plan.
- Triage workflow: ignore (with reason + risk acceptance), snooze, solve and
  severity override persisted per repository with full audit history.
- AI-executable remediation plan (`REMEDIATION_PLAN.md`) with pre-investigated
  context so coding agents can apply fixes directly.
- `verify` subcommand: re-scan and diff against baseline; exits 0 only when no
  HIGH/CRITICAL findings remain - suitable for CI gates and agent loops.
- Local web dashboard (`gatekeeper-ui`) with live scan progress, charts,
  filterable findings table, triage actions and GitHub Issue / Fix PR actions.
- GitHub integration via `gh` CLI: create issues and draft fix PRs.
- SBOM generation (CycloneDX via Syft) on every scan.

## [1.0.0] - 2026-09-14