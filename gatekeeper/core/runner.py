"""Reusable scan pipeline shared by the CLI and the web server."""
import json
from datetime import datetime, timezone
from pathlib import Path

from gatekeeper.core.detect import detect_stacks, inventory
from gatekeeper.core.normalize import build_scan_result
from gatekeeper.core.remediation import write_remediation
from gatekeeper.core.report import write_reports
from gatekeeper.core.snippets import code_snippet
from gatekeeper.scanners.scanners import TOOL_RUNNERS

GATEKEEPER_ROOT = Path(__file__).resolve().parent.parent.parent

STACK_TOOL_MAP = {
    "semgrep": ("code",),
    "trivy": ("code", "iac"),
    "gitleaks": ("code", "iac", "swift", "javascript", "python", "go"),
    "osv-scanner": ("code",),
    "checkov": ("iac",),
    "syft": ("code",),
    "grype": ("code",),
    "guarddog": ("python", "javascript"),
    "mobsf": ("swift",),
}


def select_tools(tools_arg, dast_url, stacks):
    """Resolve the tool list from an explicit --tools value or stack detection."""
    if tools_arg:
        if isinstance(tools_arg, (list, tuple)):
            requested = [str(t).strip() for t in tools_arg if str(t).strip()]
        else:
            requested = [t.strip() for t in str(tools_arg).split(",") if t.strip()]
        unknown = [t for t in requested if t not in TOOL_RUNNERS]
        if unknown:
            raise ValueError(f"Unknown tools: {', '.join(unknown)}")
        return requested
    selected = []
    for tool, relevant_stacks in STACK_TOOL_MAP.items():
        if any(stacks.get(s) for s in relevant_stacks):
            selected.append(tool)
    if dast_url:
        selected.append("zap")
        selected.append("nuclei")
    return selected


def run_scan(target, tools=None, dast_url=None, out_root=None, progress_cb=None,
             validate_secrets=False):
    """Run a full scan. Returns (ScanResult, scan_dir).

    progress_cb(event, **kwargs) is called with:
      ("scan_start", tools=[...], stacks={...}, target=str)
      ("tool_start", tool="semgrep")
      ("tool_done", tool="semgrep", count=11, note=None)
      ("scan_done", result=ScanResult, scan_dir=Path)
    """
    if progress_cb is None:
        def progress_cb(*_a, **_k):
            pass

    target = Path(target).expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"Target is not a directory: {target}")

    out_root = Path(out_root).expanduser() if out_root else GATEKEEPER_ROOT / "reports"
    scan_dir = out_root / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    raw_dir = scan_dir / "raw"

    stacks = detect_stacks(target)
    tools = select_tools(tools, dast_url, stacks)

    scope = inventory(target)
    progress_cb("scan_start", tools=tools, stacks=stacks, target=str(target),
                scope=scope)

    all_findings = []
    tools_run, tools_skipped = [], []

    for tool in tools:
        runner = TOOL_RUNNERS[tool]
        progress_cb("tool_start", tool=tool)
        try:
            findings, note = runner(target, raw_dir, dast_url=dast_url,
                                    progress_cb=progress_cb)
        except Exception as exc:  # a broken tool must not kill the whole scan
            findings, note = [], f"error: {exc}"
        if note and (note.startswith("error") or note.startswith("skipped")):
            tools_skipped.append(f"{tool} ({note})")
        else:
            tools_run.append(tool)
        progress_cb("tool_done", tool=tool, count=len(findings), note=note)
        all_findings.extend(findings)

    result = build_scan_result(
        target=target, timestamp=datetime.now(timezone.utc).isoformat(),
        stacks=stacks, tools_run=tools_run, tools_skipped=tools_skipped,
        all_findings=all_findings,
    )

    for f in result.findings:
        f.code_snippet = code_snippet(target, f.file, f.line)

    if validate_secrets:
        _validate_secrets(target, result)

    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "summary.json").write_text(json.dumps(result.to_dict(), indent=2))
    write_reports(result.to_dict(), scan_dir)
    write_remediation(result.to_dict(), scan_dir,
                      gatekeeper_path=str(GATEKEEPER_ROOT / "bin" / "gatekeeper"))

    progress_cb("scan_done", result=result, scan_dir=scan_dir)
    return result, scan_dir


def _validate_secrets(target, result):
    """Opt-in: probe leaked credentials against their providers. A confirmed
    live credential is promoted to CRITICAL/risk 100 and flagged in the report."""
    from gatekeeper.core import secretval

    for f in result.findings:
        if f.category != "secrets":
            continue
        check = secretval.validate_secret(target, f.to_dict())
        f.secret_validation = check
        if check.get("live") is True:
            f.severity = "CRITICAL"
            f.risk_score = 100
            f.title = f"{f.title} [CREDENTIAL CONFIRMED LIVE]".strip()
