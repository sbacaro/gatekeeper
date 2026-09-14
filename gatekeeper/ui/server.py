"""Gatekeeper local web server (stdlib only).

Serves the dashboard UI and a small JSON API:
  GET  /                              -> static index.html
  GET  /api/scans                     -> list of past scans
  GET  /api/scan/{id}/summary.json    -> unified findings for a scan
  GET  /api/scan/{id}/plan.md         -> AI directives text (REMEDIATION_PLAN.md)
  POST /api/browse                    -> native macOS folder picker (tkinter)
  POST /api/scan                      -> start a background scan
  GET  /api/progress                  -> status of the running scan

Security: binds to 127.0.0.1 only; only files inside reports/ are served.
"""
import json
import re
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from gatekeeper.core.runner import run_scan, GATEKEEPER_ROOT
import gatekeeper.core.issues
import gatekeeper.core.gh as gh_mod

STATIC_DIR = Path(__file__).resolve().parent / "static"
REPORTS_ROOT = GATEKEEPER_ROOT / "reports"

SCAN_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}$")

# Shared state for the single currently-running (or last finished) scan.
_scan_lock = threading.Lock()
_scan_state = {
    "status": "idle",       # idle | running | done | error
    "scan_id": None,
    "target": None,
    "tools": [],
    "events": [],           # progress log entries
    "error": None,
}


def _progress_recorder(state):
    def cb(event, **kw):
        entry = {"event": event, "ts": time.time(), **kw}
        note = kw.get("note") or ""
        if event == "tool_done" and note.startswith("error"):
            # Keep the UI readable: last line of the traceback only.
            lines = [l for l in note.splitlines() if l.strip()]
            entry["note"] = next((l for l in reversed(lines)
                                  if not l.startswith("  ") and "Traceback" not in l),
                                 lines[-1] if lines else "error")
        if event == "scan_done":
            entry["scan_dir"] = str(kw["scan_dir"])
            entry.pop("result", None)
        with _scan_lock:
            state["events"].append(entry)
            if event == "scan_done":
                state["status"] = "done"
                state["scan_id"] = kw["scan_dir"].name
    return cb


def _scan_worker(target, tools, dast_url, state):
    try:
        result, scan_dir = run_scan(
            target, tools=tools, dast_url=dast_url,
            progress_cb=_progress_recorder(state),
        )
        with _scan_lock:
            state["scan_id"] = scan_dir.name
            state["summary_counts"] = {
                sev: sum(1 for f in result.findings if f.severity == sev)
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            }
            state["total"] = len(result.findings)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        with _scan_lock:
            state["status"] = "error"
            state["error"] = f"{type(exc).__name__}: {exc}"


def list_scans():
    scans = []
    if REPORTS_ROOT.exists():
        for d in sorted(REPORTS_ROOT.iterdir(), reverse=True):
            summary = d / "summary.json"
            if d.is_dir() and summary.exists():
                try:
                    data = json.loads(summary.read_text())
                    counts = {}
                    for f in data.get("findings", []):
                        sev = f.get("severity", "INFO")
                        counts[sev] = counts.get(sev, 0) + 1
                    scans.append({
                        "id": d.name,
                        "target": data.get("target"),
                        "timestamp": data.get("timestamp"),
                        "total": len(data.get("findings", [])),
                        "counts": counts,
                    })
                except (json.JSONDecodeError, OSError):
                    continue
    return scans


def list_repos():
    """Registered repositories = every target ever scanned, with last scan."""
    repos = {}
    for scan in list_scans():
        t = scan.get("target")
        if not t:
            continue
        if t not in repos:
            repos[t] = {
                "path": t, "name": (t or "").rstrip("/").split("/")[-1],
                "last_scan_id": scan["id"], "last_scan": scan["timestamp"],
                "last_total": scan["total"], "last_counts": scan["counts"],
            }
        repos[t]["scan_count"] = repos[t].get("scan_count", 0) + 1
    return sorted(repos.values(), key=lambda r: r["last_scan"] or "", reverse=True)


def _safe_scan_file(scan_id, filename):
    """Map a logical name (plan.md) to the real file on disk."""
    FILE_MAP = {"plan.md": "REMEDIATION_PLAN.md"}
    filename = FILE_MAP.get(filename, filename)
    if not SCAN_ID_RE.match(scan_id):
        return None
    path = REPORTS_ROOT / scan_id / filename
    try:
        resolved = path.resolve()
        resolved.relative_to(REPORTS_ROOT.resolve())
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    return resolved


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ helpers --
    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, content_type="text/plain; charset=utf-8"):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return {}

    def log_message(self, fmt, *args):  # quiet
        pass

    # -------------------------------------------------------------- GET ----
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" or path == "/index.html":
            self._send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        elif path == "/api/scans":
            self._send_json(list_scans())
        elif path == "/api/progress":
            with _scan_lock:
                self._send_json(_scan_state)
        elif path == "/api/repos":
            self._send_json(list_repos())
        elif (m := re.match(r"^/api/scan/([^/]+)/(summary\.json|plan\.md|REPORT\.html)$", path)):
            fname = m.group(2)
            fpath = _safe_scan_file(m.group(1), fname)
            if fpath is None:
                self._send_json({"error": "not found"}, 404)
            elif fname == "summary.json":
                self._send_file(fpath, "application/json")
            elif fname == "REPORT.html":
                self._send_file(fpath, "text/html; charset=utf-8")
            else:
                self._send_file(fpath, "text/markdown; charset=utf-8")
        elif (m := re.match(r"^/api/scan/([^/]+)/view$", path)):
            self._handle_view(m.group(1))
        elif path == "/api/gh/status":
            self._handle_gh_status()
        elif path == "/api/history":
            self._handle_history()
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_view(self, scan_id):
        """Annotated + grouped view of a past scan."""
        fpath = _safe_scan_file(scan_id, "summary.json")
        if fpath is None:
            self._send_json({"error": "not found"}, 404)
            return
        data = json.loads(fpath.read_text())
        target = data.get("target")
        findings = data.get("findings", [])
        annotated, auto_solved = issues.annotate_findings(target, findings)
        issues.sync_seen(target, annotated)
        groups = issues.group_findings(annotated)
        for g in groups:
            g["fix_time"] = issues.estimate_fix_time(g)
        self._send_json({
            "target": target,
            "scan_id": scan_id,
            "findings": groups,
            "activity": issues.activity_stats(target, annotated),
            "config_errors": issues.config_errors(target),
            "auto_solved_count": len(auto_solved),
        })

    # ------------------------------------------------------------- POST ----
    def do_POST(self):
        if self.path == "/api/browse":
            self._handle_browse()
        elif self.path == "/api/scan":
            self._handle_scan()
        elif self.path == "/api/action":
            self._handle_action()
        elif self.path == "/api/autofix":
            self._handle_autofix()
        elif self.path == "/api/gh/issue":
            self._handle_gh_issue()
        elif self.path == "/api/gh/pr":
            self._handle_gh_pr()
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_action(self):
        body = self._read_json_body()
        target = body.get("target")
        finding = body.get("finding") or {}
        action = body.get("action")
        if not target or not finding or not action:
            self._send_json({"error": "target, finding and action are required"}, 400)
            return
        entry = issues.apply_action(
            target, finding, action,
            days=body.get("days", 7), severity=body.get("severity", ""),
            reason=body.get("reason", ""),
            risk_accepted=body.get("risk_accepted", False),
        )
        self._send_json({"ok": True, "entry": {k: v for k, v in entry.items()
                                               if k not in ("snoozed_until",)}})

    def _handle_autofix(self):
        body = self._read_json_body()
        target = body.get("target")
        finding = body.get("finding") or {}
        if not target or not finding:
            self._send_json({"error": "target and finding are required"}, 400)
            return
        prompt = issues.build_autofix_prompt(target, finding)
        self._send_json({"prompt": prompt})

    def _handle_gh_issue(self):
        body = self._read_json_body()
        target, finding = body.get("target"), body.get("finding") or {}
        if not target or not finding:
            self._send_json({"error": "target and finding are required"}, 400)
            return
        try:
            result = gh_mod.create_issue(target, finding)
            self._send_json(result)
        except gh_mod.GhError as exc:
            self._send_json({"error": str(exc)}, 400)

    def _handle_gh_pr(self):
        body = self._read_json_body()
        target, finding = body.get("target"), body.get("finding") or {}
        if not target or not finding:
            self._send_json({"error": "target and finding are required"}, 400)
            return
        prompt = issues.build_autofix_prompt(target, finding)
        try:
            result = gh_mod.create_fix_pr(target, finding, prompt)
            self._send_json(result)
        except gh_mod.GhError as exc:
            self._send_json({"error": str(exc)}, 400)

    def _handle_gh_status(self):
        from urllib.parse import parse_qs, unquote
        raw = self.path.split("?", 1)[-1] if "?" in self.path else ""
        qs = parse_qs(raw)
        target = unquote((qs.get("target") or [""])[0])
        if not target:
            self._send_json({"available": False, "error": "missing target"}, 400)
            return
        if not gh_mod.gh_available(target):
            self._send_json({"available": False})
            return
        try:
            self._send_json({"available": True, "repo": gh_mod.repo_slug(target)})
        except gh_mod.GhError as exc:
            self._send_json({"available": False, "error": str(exc)})

    def _handle_history(self):
        from urllib.parse import parse_qs
        qs = parse_qs(self.path.split("?", 1)[-1] if "?" in self.path else "")
        target = (qs.get("target") or [""])[0]
        try:
            finding = json.loads((qs.get("finding") or ["{}"])[0])
        except json.JSONDecodeError:
            finding = {}
        if not target or not finding:
            self._send_json({"error": "target and finding are required"}, 400)
            return
        self._send_json({"history": issues.issue_history(target, finding)})

    def _handle_browse(self):
        # tkinter dialogs need the main thread of their own process.
        script = (
            "import tkinter as tk; from tkinter import filedialog;"
            "root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True);"
            "print(filedialog.askdirectory(title='Select the repository to scan') or '');"
            "root.destroy()"
        )
        try:
            proc = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True, timeout=300,
            )
            chosen = ""
            if not chosen:
                chosen, err = self._browse_applescript()
                if err:
                    self._send_json({"path": "", "error": err})
                    return
            self._send_json({"path": chosen})
        except subprocess.TimeoutExpired:
            self._send_json({"path": "", "error": "folder picker timed out"}, 504)
        except Exception as exc:
            self._send_json({"path": "", "error": str(exc)}, 500)

    @staticmethod
    def _browse_applescript():
        """Native NSOpenPanel folder picker; works without tkinter.
        Returns (path, error)."""
        script = (
            'set chosenFolder to choose folder with prompt '
            '"Select the repository to scan"\n'
            'return POSIX path of chosenFolder'
        )
        try:
            proc = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode == 0:
                return proc.stdout.strip(), None
            err = (proc.stderr or "").strip()
            # User pressed Cancel (-128) -> not an error, just empty path.
            if "-128" in err or "User canceled" in err:
                return "", None
            detail = err.splitlines()[-1][:120] if err else "osascript failed"
            return "", f"folder picker unavailable ({detail})"
        except Exception as exc:
            return "", str(exc)

    def _handle_scan(self):
        body = self._read_json_body()
        target = str(body.get("path") or "").strip()
        if not target:
            self._send_json({"error": "missing path"}, 400)
            return
        target_path = Path(target).expanduser().resolve()
        if not target_path.is_dir():
            self._send_json({"error": f"not a directory: {target}"}, 400)
            return

        with _scan_lock:
            if _scan_state["status"] == "running":
                self._send_json({"error": "a scan is already running"}, 409)
                return
            _scan_state.update({
                "status": "running", "scan_id": None, "target": str(target_path),
                "tools": body.get("tools") or [], "events": [],
                "error": None, "total": None, "summary_counts": None,
            })

        thread = threading.Thread(
            target=_scan_worker,
            args=(target_path, body.get("tools") or None, body.get("dast") or None,
                  _scan_state),
            daemon=True,
        )
        thread.start()
        self._send_json({"started": True, "target": str(target_path)})


def serve(port=8695, open_browser=True):
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"Gatekeeper UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
