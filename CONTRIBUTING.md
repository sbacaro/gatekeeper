# Contributing to Gatekeeper

Thanks for your interest in contributing! This document explains how to set up
a development environment and the conventions used in this repository.

## Development setup

```bash
git clone https://github.com/sbacaro/gatekeeper.git
cd gatekeeper

# System scanners (macOS)
./install.sh

# Verify the CLI works
./bin/gatekeeper scan ./sample-vulnerable-app
```

## Project layout

```
bin/                 Executable entry points
gatekeeper/          Python package
  core/              Scan pipeline, CLI, reporting, triage, GitHub integration
  scanners/          Per-tool scanner runners
  ui/                Local web dashboard (stdlib HTTP server + static HTML)
  rules/             Custom Semgrep rules shipped with Gatekeeper
docs/                Documentation
sample-vulnerable-app/  Intentionally vulnerable demo app for testing scans
```

## Conventions

- Python 3.9+ standard library only for the core and UI - no runtime pip
  dependencies. External scanners are invoked as subprocesses.
- Every scanner runner returns normalized `Finding` objects and writes its raw
  JSON output into the scan's `raw/` directory.
- A broken tool must never abort the whole scan; errors are surfaced as
  skipped-tool notes.
- All code and comments in English.

## Pull requests

1. Fork the repo and create a feature branch from `main`.
2. Keep the change focused; one logical change per PR.
3. Run a self-scan before submitting: `./bin/gatekeeper scan ./sample-vulnerable-app`
   should behave as before your change.
4. Describe what changed and why; link any related issue.
5. By submitting a PR you agree your contribution is licensed under the
   PolyForm Noncommercial License 1.0.0, same as the rest of the project.

## Reporting bugs

Open a [bug report](https://github.com/sbacaro/gatekeeper/issues/new?template=bug_report.md)
with the Gatekeeper version, the tools involved and the relevant snippet of
`summary.json` (redact anything sensitive).
