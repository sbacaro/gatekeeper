"""Gatekeeper CLI: scan, verify, ci and sarif subcommands."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from gatekeeper.core.diffscan import diff_findings, load_baseline, restrict_to_changed
from gatekeeper.core.runner import GATEKEEPER_ROOT, run_scan
from gatekeeper.core.sarif import sarif_report


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="gatekeeper", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("path", help="Target project directory")
        p.add_argument("--dast", default=None, help="URL to DAST-scan with OWASP ZAP")
        p.add_argument("--tools", default=None,
                       help="Comma-separated tool list (default: auto by stack)")
        p.add_argument("--output", default=None, help="Reports output directory")
        p.add_argument("--baseline", default=None,
                       help="Path to a previous summary.json to diff against (verify)")
        p.add_argument("--validate-secrets", action="store_true",
                       help="Check leaked credentials against provider APIs "
                            "(generates provider audit-log events)")

    common(sub.add_parser("scan", help="Run a full security scan"))
    common(sub.add_parser("verify", help="Re-scan and diff against last scan"))
    p_ci = sub.add_parser(
        "ci", help="Diff-aware scan for pull requests (SARIF out, PR annotations)")
    common(p_ci)
    p_ci.add_argument("--base", default="origin/main",
                      help="Git ref to diff against (default: origin/main)")
    p_ci.add_argument("--sarif-out", default="gatekeeper.sarif",
                      help="Where to write the SARIF file (default: ./gatekeeper.sarif)")
    p_sarif = sub.add_parser("sarif", help="Print the SARIF of the latest scan to stdout")
    p_sarif.add_argument("path", help="Target project directory")
    p_sarif.add_argument("--baseline", default=None,
                         help="Path to a previous summary.json to convert instead")
    p_sarif.add_argument("--tools", default=None)
    p_sarif.add_argument("--dast", default=None)
    p_sarif.add_argument("--output", default=None)
    p_fix = sub.add_parser(
        "fix", help="Autofix vulnerable dependencies (SCA), verify and open a PR")
    common(p_fix)
    p_fix.add_argument("--max", type=int, default=20,
                       help="Max dependency bumps per run (default: 20)")
    p_fix.add_argument("--no-pr", action="store_true",
                       help="Apply bumps locally without opening a PR")
    sub.add_parser("mcp", help="Run the Gatekeeper MCP server (for coding agents)")
    return parser.parse_args(argv)


def _print_progress(event, **kw):
    if event == "scan_start":
        active = ", ".join(k for k, v in kw["stacks"].items() if v and k != "code") or "none"
        print(f"Gatekeeper scan of {kw['target']}")
        print(f"  stacks detected : {active}")
        print(f"  tools selected  : {', '.join(kw['tools']) or 'none'}")
        print()
    elif event == "tool_start":
        print(f"-> {kw['tool']} ...", flush=True)
    elif event == "tool_done":
        if kw.get("note"):
            print(f"   {kw['note']}")
        print(f"   findings: {kw['count']}")
    elif event == "scan_done":
        result = kw["result"]
        counts = {}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print()
        print(f"Scan complete: {len(result.findings)} findings  "
              f"(CRITICAL={counts.get('CRITICAL', 0)} HIGH={counts.get('HIGH', 0)} "
              f"MEDIUM={counts.get('MEDIUM', 0)} LOW={counts.get('LOW', 0)})")
        print(f"Reports saved to: {kw['scan_dir']}")
        print(f"AI directives file: {kw['scan_dir'] / 'REMEDIATION_PLAN.md'}")


def _run_scan(args):
    try:
        return run_scan(args.path, tools=args.tools, dast_url=args.dast,
                        out_root=args.output, progress_cb=_print_progress,
                        validate_secrets=getattr(args, "validate_secrets", False))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)


def _load_latest_baseline(target, explicit_baseline):
    candidates = []
    if explicit_baseline:
        candidates.append(Path(explicit_baseline))
    else:
        reports_root = GATEKEEPER_ROOT / "reports"
        if reports_root.exists():
            candidates = sorted(
                (d / "summary.json" for d in reports_root.iterdir()
                 if d.is_dir() and (d / "summary.json").exists()),
                key=lambda p: p.parent.name,
            )
    for candidate in reversed(candidates):
        try:
            data = json.loads(candidate.read_text())
            if str(target) == data.get("target"):
                return data, candidate.parent
        except (json.JSONDecodeError, OSError):
            continue
    return None, None


def _diff_findings(baseline_findings, new_findings):
    def key(f):
        return (f.get("category"), f.get("file"), f.get("line"), f.get("title", "").lower())

    baseline = {key(f): f for f in baseline_findings}
    new_map = {key(f): f for f in new_findings}

    fixed = [f for k, f in baseline.items() if k not in new_map]
    new = [f for k, f in new_map.items() if k not in baseline]
    remaining = [f for k, f in new_map.items() if k in baseline]
    return new, fixed, remaining


def cmd_verify(args):
    target = Path(args.path).expanduser().resolve()
    baseline, baseline_dir = _load_latest_baseline(target, args.baseline)

    result, scan_dir = _run_scan(args)

    if baseline_dir is not None:
        baseline_dir = Path(baseline_dir).resolve()
    if baseline is None or baseline_dir == scan_dir.resolve():
        print("\nNo previous scan found for this target - verification baseline created.")
        print("Tip: this scan IS the baseline. Apply the remediation plan, then run verify again.")
        return _exit_code([f.to_dict() for f in result.findings])

    new, fixed, remaining = _diff_findings(baseline.get("findings", []),
                                           [f.to_dict() for f in result.findings])

    print("\n=== Verification ===")
    print(f"Baseline: {baseline_dir.name}  ->  Current: {scan_dir.name}")
    print(f"  fixed     : {len(fixed)}")
    for f in fixed:
        print(f"    [FIXED]    [{f['severity']}] {f['title']} ({f.get('file', 'n/a')})")
    print(f"  new       : {len(new)}")
    for f in new:
        print(f"    [NEW]      [{f['severity']}] {f['title']} ({f.get('file', 'n/a')})")
    print(f"  remaining : {len(remaining)}")
    for f in remaining:
        print(f"    [OPEN]     [{f['severity']}] {f['title']} ({f.get('file', 'n/a')})")

    blocking = [f for f in new + remaining if f["severity"] in ("CRITICAL", "HIGH")]
    if blocking:
        print(f"\nVERIFY FAILED: {len(blocking)} HIGH/CRITICAL finding(s) still open.")
        print("Continue with the remediation plan and run verify again.")
    else:
        print("\nVERIFY PASSED: no HIGH/CRITICAL findings remain.")
    return _exit_code(new + remaining)


def _git_changed_files(target: Path, base_ref: str) -> list:
    """Files changed between base_ref and the working tree."""
    def git(*args):
        try:
            proc = subprocess.run(["git", *args], cwd=str(target),
                                  capture_output=True, text=True, timeout=60)
            return proc.stdout if proc.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""

    names = set()
    out = git("diff", "--name-only", base_ref)
    names.update(ln for ln in out.splitlines() if ln.strip())
    out = git("diff", "--name-only", "--cached")
    names.update(ln for ln in out.splitlines() if ln.strip())
    return sorted(names)


def cmd_ci(args):
    """PR gate: full scan, then keep only findings introduced by this change.

    Emits a SARIF file ready for upload to GitHub Code Scanning and fails the
    build when NEW HIGH/CRITICAL findings are present (pre-existing debt does
    not block - that is what `verify` is for).
    """
    target = Path(args.path).expanduser().resolve()

    baseline_path = args.baseline
    baseline = load_baseline(baseline_path) if baseline_path else None
    if baseline is None:
        _, baseline_dir = _load_latest_baseline(target, None)
        if baseline_dir:
            baseline = load_baseline(Path(baseline_dir) / "summary.json")

    result, scan_dir = _run_scan(args)
    current = [f.to_dict() for f in result.findings]
    changed_files = _git_changed_files(target, args.base)

    if baseline is None:
        print("\nNo baseline found - reporting all findings (CI acts like verify).")
        reportable = current
    else:
        d = diff_findings(baseline, current)
        reportable = restrict_to_changed(d["new"], changed_files)
        print(f"\n=== CI diff-aware gate (base: {args.base}) ===")
        print(f"  changed files      : {len(changed_files)}")
        print(f"  new findings       : {len(d['new'])}")
        print(f"  in changed files   : {len(reportable)}")
        for f in reportable:
            print(f"    [NEW] [{f['severity']}] {f['title']} ({f.get('file', 'n/a')})")

    sarif_path = Path(args.sarif_out)
    sarif_path.write_text(json.dumps(
        sarif_report({**result.to_dict(), "findings": reportable}), indent=2))
    print(f"\nSARIF written to: {sarif_path}")
    print("Upload to GitHub Code Scanning with:")
    print("  gh api repos/<owner>/<repo>/code-scanning/sarifs "
          "-f ref=refs/heads/<branch> -f commit_sha=$GITHUB_SHA "
          f"-f sarif=@{sarif_path}")

    blocking = [f for f in reportable if f["severity"] in ("CRITICAL", "HIGH")]
    if blocking:
        print(f"\nCI FAILED: {len(blocking)} new HIGH/CRITICAL finding(s) in this change.")
        return 1
    print("\nCI PASSED: no new HIGH/CRITICAL findings in this change.")
    return 0


def cmd_sarif(args):
    """Print SARIF of the latest scan for the target (or run one if needed)."""
    target = str(Path(args.path).expanduser().resolve())
    if args.baseline:
        baseline = load_baseline(args.baseline)
    else:
        baseline, _ = _load_latest_baseline(Path(target), None)
    if baseline is None:
        result, _ = _run_scan(args)
        data = sarif_report(result.to_dict())
    else:
        data = sarif_report(baseline)
    json.dump(data, sys.stdout, indent=2)
    print()
    return 0


def _exit_code(findings):
    def sev(f):
        return f["severity"] if isinstance(f, dict) else f.severity
    return 1 if any(sev(f) in ("CRITICAL", "HIGH") for f in findings) else 0


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.command == "scan":
            result, _ = _run_scan(args)
            return _exit_code(result.findings)
        if args.command == "verify":
            return cmd_verify(args)
        if args.command == "ci":
            return cmd_ci(args)
        if args.command == "sarif":
            return cmd_sarif(args)
        if args.command == "fix":
            from gatekeeper.core.autofix import autofix_loop
            return autofix_loop(args.path, max_fixes=args.max,
                                open_pr=not args.no_pr)
        if args.command == "mcp":
            from gatekeeper.mcp.server import serve
            return serve()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 2
    return 2
