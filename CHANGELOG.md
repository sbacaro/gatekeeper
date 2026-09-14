# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
