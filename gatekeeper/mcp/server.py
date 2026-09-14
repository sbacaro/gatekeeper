"""Gatekeeper MCP server (stdio, JSON-RPC 2.0, zero dependencies).

Exposes Gatekeeper as native tools to any MCP client (Cursor, Claude Code,
Copilot Workspace, ...):
  - gatekeeper_scan        run (or re-run) a full scan of a repository
  - gatekeeper_list        latest findings, filtered by severity/status
  - gatekeeper_finding     full detail of one finding (snippet, recon, plan)
  - gatekeeper_triage      ignore / snooze / solve / severity override
  - gatekeeper_verify      re-scan + diff against baseline, exit-code semantics
  - gatekeeper_plan        the AI remediation plan (REMEDIATION_PLAN.md)

Run with:  gatekeeper mcp
"""
import json
from pathlib import Path

from gatekeeper.core import issues
from gatekeeper.core.runner import run_scan

SERVER_INFO = {"name": "gatekeeper", "version": "1.0.0"}

TOOLS = [
    {
        "name": "gatekeeper_scan",
        "description": "Run a full Gatekeeper security scan (SAST, SCA, secrets, "
                       "IaC, DAST) on a repository. Returns the unified summary "
                       "with risk scores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute repository path"},
                "tools": {"type": "string",
                          "description": "Optional comma-separated tool list"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "gatekeeper_list",
        "description": "List findings from the latest scan of a repository, "
                       "sorted by risk score. Filter by severity or status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute repository path"},
                "severity": {"type": "string",
                             "description": "Filter: CRITICAL|HIGH|MEDIUM|LOW|INFO"},
                "status": {"type": "string",
                           "description": "Filter: open|new|ignored|snoozed|solved"},
                "limit": {"type": "integer", "description": "Max findings to return"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "gatekeeper_finding",
        "description": "Full detail of one finding: code snippet, threat intel "
                       "(KEV/EPSS), remediation directives and audit history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "id": {"type": "string", "description": "Finding id or title substring"},
            },
            "required": ["path", "id"],
        },
    },
    {
        "name": "gatekeeper_triage",
        "description": "Triage a finding: ignore (with reason/risk acceptance), "
                       "snooze for N days, mark solved, or override severity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "id": {"type": "string", "description": "Finding id or title substring"},
                "action": {"type": "string",
                           "enum": ["ignore", "unignore", "snooze", "unsnooze",
                                    "solve", "unsolve", "severity"]},
                "reason": {"type": "string"},
                "days": {"type": "integer"},
                "severity": {"type": "string"},
                "risk_accepted": {"type": "boolean"},
            },
            "required": ["path", "id", "action"],
        },
    },
    {
        "name": "gatekeeper_verify",
        "description": "Re-scan the repository and diff against the previous "
                       "baseline. Returns PASSED only when no HIGH/CRITICAL "
                       "findings remain - use in agent fix loops.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "gatekeeper_plan",
        "description": "Return the AI remediation plan (REMEDIATION_PLAN.md) of "
                       "the latest scan, with pre-investigated context per finding.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


# ------------------------------------------------------------------ state ---

def _latest_summary(target: str) -> dict | None:
    from gatekeeper.core.cli import _load_latest_baseline
    data, _ = _load_latest_baseline(Path(target), None)
    return data


def _find_finding(summary: dict, needle: str) -> dict | None:
    for f in summary.get("findings", []):
        if f.get("id") == needle:
            return f
    lowered = needle.lower()
    for f in summary.get("findings", []):
        if lowered in (f.get("title") or "").lower():
            return f
    return None


# ------------------------------------------------------------------ tools ---

def tool_scan(args: dict) -> dict:
    target = args["path"]
    result, scan_dir = run_scan(
        target, tools=args.get("tools"),
        progress_cb=lambda *a, **k: None,
    )
    findings = [f.to_dict() for f in result.findings]
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "scan_id": scan_dir.name,
        "reports_dir": str(scan_dir),
        "total": len(findings),
        "counts": counts,
        "top_findings": findings[:25],
    }


def tool_list(args: dict) -> dict:
    summary = _latest_summary(args["path"])
    if summary is None:
        return {"error": "no scan found for this target; run gatekeeper_scan first"}
    findings = summary.get("findings", [])
    sev = args.get("severity")
    status = args.get("status")
    if sev:
        findings = [f for f in findings if f.get("severity") == sev.upper()]
    if status:
        annotated, _ = issues.annotate_findings(summary["target"], findings)
        findings = [f for f in annotated if f.get("status") == status]
    limit = int(args.get("limit") or 50)
    return {
        "target": summary["target"],
        "scan_id": Path(summary.get("_dir", "")).name if summary.get("_dir") else None,
        "total": len(findings),
        "findings": [{
            "id": f.get("id"), "severity": f.get("severity"),
            "title": f.get("title"), "file": f.get("file"), "line": f.get("line"),
            "risk_score": f.get("risk_score"), "kev": f.get("kev", False),
            "epss": f.get("epss"),
        } for f in findings[:limit]],
    }


def tool_finding(args: dict) -> dict:
    summary = _latest_summary(args["path"])
    if summary is None:
        return {"error": "no scan found for this target; run gatekeeper_scan first"}
    f = _find_finding(summary, args["id"])
    if f is None:
        return {"error": f"finding not found: {args['id']}"}
    f["history"] = issues.issue_history(summary["target"], f)
    return f


def tool_triage(args: dict) -> dict:
    summary = _latest_summary(args["path"])
    if summary is None:
        return {"error": "no scan found for this target; run gatekeeper_scan first"}
    f = _find_finding(summary, args["id"])
    if f is None:
        return {"error": f"finding not found: {args['id']}"}
    entry = issues.apply_action(
        summary["target"], f, args["action"],
        reason=args.get("reason", ""),
        days=args.get("days", 7),
        severity=args.get("severity", ""),
        risk_accepted=bool(args.get("risk_accepted", False)),
    )
    return {"ok": True, "issue_key": issues.issue_key(f, summary["target"]),
            "entry": {k: v for k, v in entry.items() if k != "snoozed_until"}}


def tool_verify(args: dict) -> dict:
    from gatekeeper.core.cli import cmd_verify, parse_args
    argv = ["verify", args["path"]]
    args_ns = parse_args(argv)
    code = cmd_verify(args_ns)
    return {"exit_code": code,
            "verdict": "PASSED" if code == 0 else "FAILED"}


def tool_plan(args: dict) -> dict:
    from gatekeeper.core.cli import _load_latest_baseline
    _, baseline_dir = _load_latest_baseline(Path(args["path"]), None)
    if baseline_dir is None:
        return {"error": "no scan found for this target; run gatekeeper_scan first"}
    plan = (Path(baseline_dir) / "REMEDIATION_PLAN.md").read_text()
    return {"plan": plan}


TOOL_HANDLERS = {
    "gatekeeper_scan": tool_scan,
    "gatekeeper_list": tool_list,
    "gatekeeper_finding": tool_finding,
    "gatekeeper_triage": tool_triage,
    "gatekeeper_verify": tool_verify,
    "gatekeeper_plan": tool_plan,
}


# ------------------------------------------------------------------- JSON-RPC

def _reply(msg_id, result):
    print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}), flush=True)


def _error(msg_id, code, message):
    print(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                      "error": {"code": code, "message": message}}), flush=True)


def handle(request: dict):
    method = request.get("method", "")
    msg_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        _reply(msg_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })
    elif method == "notifications/initialized" or method.startswith("notifications/"):
        pass  # notifications get no response
    elif method == "tools/list":
        _reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name")
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            _error(msg_id, -32602, f"unknown tool: {name}")
            return
        try:
            result = handler(params.get("arguments") or {})
            _reply(msg_id, {
                "content": [{"type": "text",
                             "text": json.dumps(result, indent=2, default=str)}],
            })
        except Exception as exc:
            _reply(msg_id, {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            })
    elif method == "ping":
        _reply(msg_id, {})
    else:
        if msg_id is not None:
            _error(msg_id, -32601, f"method not found: {method}")


def serve() -> int:
    """Run the MCP server on stdio until EOF."""
    for line in __import__("sys").stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            _error(None, -32700, "parse error")
            continue
        handle(request)
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
