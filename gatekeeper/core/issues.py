"""Persistent per-repository issue state, grouped issues, fix-time estimates
and configuration error checks - the commercial-platform-parity layer.

State lives in <repo>/.gatekeeper-state.json so it survives across scans and
machine restarts.
"""
import json
import re
import time
from pathlib import Path

STATE_FILE = ".gatekeeper-state.json"

CAT_L = {"sast": "Code", "sca": "Dependency", "secrets": "Secret",
         "iac": "Infrastructure", "dast": "Runtime"}

# ---------------------------------------------------------------- state ----

def _state_path(target: Path) -> Path:
    return Path(target) / STATE_FILE


def load_state(target) -> dict:
    path = _state_path(target)
    default = {"issues": {}, "repos": {}, "updated_at": None}
    try:
        data = json.loads(path.read_text())
        data.setdefault("issues", {})
        return data
    except (json.JSONDecodeError, OSError):
        return default


def save_state(target, state: dict):
    state["updated_at"] = time.time()
    try:
        _state_path(target).write_text(json.dumps(state, indent=2))
    except OSError:
        pass


def issue_key(finding: dict, target=None) -> str:
    """Stable identity of a finding across scans. File paths are normalized to
    be target-relative so scanners reporting absolute vs relative paths still
    map to the same issue."""
    file = (finding.get("file") or "").strip()
    if target and file:
        try:
            file = str(Path(file).resolve().relative_to(Path(target).resolve()))
        except (ValueError, OSError):
            file = file.split("/")[-1]  # fallback: basename
    raw = f"{finding.get('category')}|{file}|{finding.get('line')}|" \
          f"{(finding.get('title') or '').lower()}"
    return re.sub(r"\s+", " ", raw)[:220]


def apply_action(target, finding: dict, action: str, **kwargs) -> dict:
    """Record ignore / unsnooze / solve / unsolve / severity on one issue.
    Every action is appended to a per-issue history (audit trail)."""
    state = load_state(target)
    key = issue_key(finding, target)
    entry = state["issues"].setdefault(key, {"first_seen": time.time()})
    now = time.time()
    if action == "ignore":
        entry["ignored"] = True
        entry["ignored_at"] = now
        entry["reason"] = kwargs.get("reason", "")
        entry["risk_accepted"] = bool(kwargs.get("risk_accepted", False))
    elif action == "unignore":
        entry["ignored"] = False
        entry.pop("risk_accepted", None)
    elif action == "snooze":
        entry["snoozed_until"] = now + kwargs.get("days", 7) * 86400
    elif action == "unsnooze":
        entry.pop("snoozed_until", None)
    elif action == "solve":
        entry["solved"] = True
        entry["solved_at"] = now
        entry.pop("ignored", None)
    elif action == "unsolve":
        entry["solved"] = False
        entry.pop("solved_at", None)
    elif action == "severity":
        entry["severity_override"] = kwargs.get("severity", "").upper()
    entry["last_seen"] = now
    entry.setdefault("history", []).append({
        "action": action, "ts": now,
        "reason": kwargs.get("reason", ""),
        "severity": kwargs.get("severity", ""),
        "risk_accepted": bool(kwargs.get("risk_accepted", False)) if action == "ignore" else None,
        "title": (finding.get("title") or "")[:120],
    })
    save_state(target, state)
    return entry


def issue_history(target, finding: dict) -> list:
    """Audit trail of triage actions on one issue."""
    state = load_state(target)
    entry = state["issues"].get(issue_key(finding, target), {})
    return entry.get("history", [])


def annotate_findings(target, findings: list) -> list:
    """Attach persistent status to each finding:
    status: open | ignored | snoozed | solved | new
    plus severity_override and solved/auto_solved bookkeeping.
    Mirrors the scan flow of commercial platforms: disappeared issues become auto-solved.
    """
    state = load_state(target)
    issues = state["issues"]
    now = time.time()
    seen_keys = set()
    out = []
    auto_solved = []

    for f in findings:
        key = issue_key(f, target)
        seen_keys.add(key)
        entry = issues.get(key, {})

        sev = entry.get("severity_override") or f.get("severity")
        item = dict(f)
        item["state_key"] = key

        if entry.get("solved"):
            item["status"] = "solved"
        elif entry.get("snoozed_until") and entry["snoozed_until"] > now:
            item["status"] = "snoozed"
            item["snoozed_until"] = entry["snoozed_until"]
        elif entry.get("ignored"):
            item["status"] = "ignored"
            item["reason"] = entry.get("reason", "")
            item["risk_accepted"] = bool(entry.get("risk_accepted"))
        else:
            item["status"] = "new" if not entry else "open"
        item["severity"] = sev
        item["first_seen"] = entry.get("first_seen")
        item["solved_at"] = entry.get("solved_at")
        out.append(item)

    # Issues known in state but absent now -> auto solved (like the big platforms).
    for key, entry in issues.items():
        if key in seen_keys:
            continue
        if entry.get("solved"):
            continue
        if entry.get("status") in ("open", "new"):
            entry["solved"] = True
            entry["solved_at"] = now
            entry["auto_solved"] = True
            entry["status"] = "solved"
            auto_solved.append(key)

    if auto_solved:
        save_state(target, state)
    return out, auto_solved


def sync_seen(target, annotated: list):
    """Persist last_seen / status for every finding present in this scan."""
    state = load_state(target)
    issues = state["issues"]
    now = time.time()
    for f in annotated:
        entry = issues.setdefault(f["state_key"], {"first_seen": now})
        entry["last_seen"] = now
        entry["status"] = f["status"]
        entry.setdefault("title", f.get("title", ""))
        entry.setdefault("file", f.get("file", ""))
        entry.setdefault("severity", f.get("severity", ""))
    save_state(target, state)


def activity_stats(target, annotated: list) -> dict:
    """New / solved / ignored counts within the last 7 days (dashboard activity strip)."""
    now = time.time()
    week = 7 * 86400
    state = load_state(target)
    solved_week = sum(
        1 for e in state["issues"].values()
        if e.get("solved_at") and now - e["solved_at"] <= week
    )
    ignored_week = sum(
        1 for e in state["issues"].values()
        if e.get("ignored_at") and now - e["ignored_at"] <= week
    )
    new_week = sum(1 for f in annotated if f.get("status") == "new")
    return {"new": new_week, "solved": solved_week, "ignored": ignored_week}


# ------------------------------------------------------------- grouping ----

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _group_key(f: dict):
    cat = f.get("category")
    title = (f.get("title") or "")
    if cat == "sca":
        m = _CVE_RE.search(title)
        pkg = None
        m2 = re.search(r" in ([\w.\-]+)@", title)
        if m2:
            pkg = m2.group(1)
        if m:
            return ("sca", m.group(0).upper(), pkg)
    if cat == "secrets":
        m = re.match(r"Secret: (\S+)", title)
        if m:
            return ("secrets", m.group(1))
    if cat == "iac":
        m = re.match(r"(DS-\d+)", title)
        if m:
            return ("iac", m.group(1))
    return (cat, f.get("file"), f.get("line"), title.lower()[:60])


def group_findings(annotated: list) -> list:
    """Collapse issues the way leading AppSec platforms do: CVEs of the same
    package count as one group; the same secret across N files is one group."""
    groups = {}
    order = []
    for f in annotated:
        if f.get("status") in ("ignored", "snoozed"):
            gkey = ("__solo__", id(f))
        else:
            gkey = _group_key(f)
        if gkey not in groups:
            groups[gkey] = {"items": [f], "key": gkey}
            order.append(gkey)
        else:
            groups[gkey]["items"].append(f)

    out = []
    for gkey in order:
        items = groups[gkey]["items"]
        primary = max(items, key=lambda f: _sev_rank(f.get("severity")))
        group = dict(primary)
        group["members"] = items
        if len(items) > 1:
            files = sorted({i.get("file") for i in items if i.get("file")})
            if len(files) > 1:
                group["title"] = (
                    f"{primary['title']} (+{len(items)-1} similar in {len(files)} files)"
                )
            else:
                group["title"] = f"{primary['title']} (+{len(items)-1} similar)"
        group["group_size"] = len(items)
        out.append(group)
    return out


def _sev_rank(sev):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, 0)


# ------------------------------------------------------------ fix time -----

def estimate_fix_time(f: dict) -> str:
    """Rough human estimate of fix effort."""
    cat = f.get("category")
    sev = f.get("severity")
    if cat == "secrets":
        return "15 min" if sev in ("CRITICAL", "HIGH") else "30 min"
    if cat == "sca":
        return "5 min"
    if cat == "iac":
        return "10 min" if f.get("severity") in ("HIGH", "CRITICAL") else "20 min"
    if cat == "dast":
        return "1 hr"
    # sast: heuristic by vulnerability class
    title = (f.get("title") or "").lower()
    if any(w in title for w in ("injection", "rce", "deserializ", "command")):
        return "6 hr"
    if any(w in title for w in ("xss", "csrf", "redirect", "open")):
        return "1 hr"
    if any(w in title for w in ("access control", "auth", "jwt", "token")):
        return "4 hr"
    if any(w in title for w in ("validation", "information", "error message")):
        return "2 hr"
    return "2 hr"


# ------------------------------------------------------- config errors -----

def config_errors(target) -> list:
    """Cheap heuristics for repository-level hygiene problems that weaken the
    scan itself (shown separately from code issues, before the results)."""
    target = Path(target)
    errors = []

    def has(*names):
        return any((target / n).exists() for n in names)

    # Lockfile check. Swift's Package.resolved counts as a lockfile: without
    # this, every Swift package would report a false "missing lockfile".
    manifest = has("package.json", "requirements.txt", "pyproject.toml",
                   "Package.swift", "go.mod", "pom.xml", "Cargo.toml")
    lockfile = has("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                   "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum",
                   "Package.resolved")
    if manifest and not lockfile:
        errors.append({
            "title": "Missing lockfile",
            "detail": "A dependency manifest exists but no lockfile was found. Commit a "
                      "lockfile (package-lock.json, Cargo.lock, Package.resolved, ...) so "
                      "dependency CVE scans are complete and builds are reproducible.",
            "severity": "MEDIUM",
            "hint": "Commit your lockfile to git.",
        })

    for env_name in (".env", ".env.local", ".env.production"):
        env_path = target / env_name
        if env_path.exists():
            gitignore = target / ".gitignore"
            ignored = gitignore.exists() and env_name in gitignore.read_text()
            if not ignored:
                errors.append({
                    "title": f"{env_name} not gitignored",
                    "detail": f"{env_name} exists and is not listed in .gitignore. Environment "
                              "files usually contain credentials and must never be committed.",
                    "severity": "HIGH",
                    "hint": f'Add "{env_name}" to .gitignore and rotate '
                            "any credentials it contains.",
                })

    return errors


# ------------------------------------------------------------- autofix -----

def build_autofix_prompt(target, finding: dict) -> str:
    """Per-issue AI prompt containing the real code around the finding and,
    for secrets, the pre-investigated git context so the agent does not have
    to search for files or guess verification mechanics."""
    import recon as recon_mod
    file_path = Path(target) / finding.get("file", "")
    snippet = ""
    line = finding.get("line") or 0
    if finding.get("file") and file_path.exists() and line:
        try:
            lines = file_path.read_text().splitlines()
            start = max(0, line - 6)
            end = min(len(lines), line + 5)
            numbered = "\n".join(
                f"{i+1:4d}| {lines[i]}" for i in range(start, end)
            )
            snippet = f"\nCurrent code ({finding['file']}):\n```\n{numbered}\n```\n"
        except OSError:
            snippet = ""

    cat = finding.get("category", "sast")
    fix_hint = finding.get("remediation_hint", "")

    recon_block = ""
    if cat == "secrets":
        info = recon_mod.secret_recon(target, finding)
        recon_block = (
            "\nPRE-INVESTIGATED CONTEXT (facts - do NOT spend turns re-checking):\n"
            + recon_mod.format_secret_context(info) + "\n"
        )
        if not info.get("in_working_tree") and info.get("file"):
            recon_block += (
                f"\nIMPORTANT: `{finding.get('file')}` does not exist on disk. "
                "The secret is only in git history. The fix is history rewrite "
                "(git filter-repo / BFG), NOT editing the file.\n"
            )

    return f"""Fix the following security issue in the repository at {target}.

ISSUE [{finding.get('severity')} - {CAT_L.get(cat, cat)}] {finding.get('title')}
File: {finding.get('file')}:{finding.get('line')}
Scanner suggestion: {fix_hint}
{recon_block}{snippet}
DIRECTIVES:
1. Apply the minimal secure fix - do not refactor unrelated code.
2. Keep the existing behavior for valid inputs.
3. If the issue is a secret: remove it, load it from an environment variable or
   build setting, rotate the credential at the provider, and clean git history
   as described in the context above (do not print the secret value).
4. After the fix, run the project's checks/tests if available.

When done, verify with: ./gatekeeper verify {target}
"""
