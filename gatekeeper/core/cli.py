"""Gatekeeper CLI: scan and verify subcommands."""
import argparse
import json
import sys
from pathlib import Path

from gatekeeper.core.runner import GATEKEEPER_ROOT, run_scan

STACK_TOOL_MAP_FOR_DOCS = "auto-selected by detected stack"


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

    common(sub.add_parser("scan", help="Run a full security scan"))
    common(sub.add_parser("verify", help="Re-scan and diff against last scan"))
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
                        out_root=args.output, progress_cb=_print_progress)
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
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 2
    return 2
