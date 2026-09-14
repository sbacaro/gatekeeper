"""Pre-investigate each finding so the AI plan carries concrete facts instead
of instructions to "go look". For secrets: which commits contain the file,
whether they are pushed, whether the file still exists, which gitleaks passes
will still flag it, and the exact history-rewrite commands. The goal is that
the Cursor agent never needs to rediscover what Gatekeeper already knows.
"""
import shutil
import subprocess
from pathlib import Path


def _git(target: Path, *args: str, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=str(target), capture_output=True,
            text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            return ""
        return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _current_branch(target: Path) -> str:
    return _git(target, "rev-parse", "--abbrev-ref", "HEAD")


def _remote_url(target: Path) -> str:
    return _git(target, "remote", "get-url", "origin")


def _branch_pushed(target: Path, branch: str) -> bool:
    if not branch or branch == "HEAD":
        return False
    return bool(_git(target, "rev-parse", "--verify", f"origin/{branch}"))


def _is_pushed(target: Path, commit_hash: str) -> bool:
    """True if the commit is reachable from any remote-tracking branch."""
    if not commit_hash:
        return False
    return bool(_git(target, "branch", "-r", "--contains", commit_hash))


def _commits_touching(target: Path, file: str) -> list:
    out = _git(target, "log", "--all", "--follow",
               "--format=%H%x00%h%x00%an%x00%ad%x00%s",
               "--date=short", "--", file)
    commits = []
    for line in out.splitlines():
        parts = line.split("\x00")
        if len(parts) >= 5:
            commits.append({
                "hash": parts[0], "short": parts[1], "author": parts[2],
                "date": parts[3], "subject": parts[4],
            })
    return commits


def _line_at(target: Path, file: str, line: int) -> str:
    try:
        lines = (target / file).read_text(errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
    except OSError:
        pass
    return ""


def _pickaxe_commits(target: Path, needle: str, limit: int = 5) -> list:
    """Commits where `needle` was added or removed (-S pickaxe)."""
    if not needle or len(needle) < 12:
        return []
    out = _git(target, "log", "--all", f"-S{needle}",
               "--format=%h|%ad|%s", "--date=short")
    return [ln for ln in out.splitlines() if ln.strip()][:limit]


def secret_recon(target, finding: dict) -> dict:
    """Everything an agent needs to fix one secret finding in one pass."""
    target = Path(target)
    file = finding.get("file", "")
    line = finding.get("line") or 0
    info = {
        "file": file,
        "line": line,
        "in_working_tree": bool(file) and (target / file).exists(),
        "is_git_repo": (target / ".git").exists(),
        "branch": None,
        "remote": None,
        "branch_pushed": False,
        "commits": [],
        "secret_commits": [],
        "filter_repo_available": bool(shutil.which("git-filter-repo")),
        "bfg_available": bool(shutil.which("bfg")),
    }
    if not info["is_git_repo"]:
        return info

    branch = _current_branch(target)
    info["branch"] = branch
    info["remote"] = _remote_url(target)
    info["branch_pushed"] = _branch_pushed(target, branch)

    if not file:
        return info

    commits = _commits_touching(target, file)
    for c in commits:
        c["pushed"] = _is_pushed(target, c["hash"])
    info["commits"] = commits

    # Locate the exact commits that added/removed the secret content via
    # pickaxe on the current line content (when the file still exists).
    snippet = _line_at(target, file, line)
    if snippet:
        info["secret_commits"] = _pickaxe_commits(target, snippet)
    else:
        # File deleted from working tree: find content in history blobs.
        # We cannot know the secret value (redacted), so expose the commits
        # and let the plan instruct a content search inside them.
        info["secret_commits"] = []
    return info


def format_secret_context(info: dict) -> str:
    """Render the recon dict as ready-to-paste facts + commands for the plan."""
    lines = []
    if not info.get("is_git_repo"):
        lines.append("- Not a git repository: no history cleanup needed; just "
                     "remove the secret from the file.")
        return "\n".join(lines)

    wt = info.get("in_working_tree")
    if wt:
        lines.append(f"- File present in working tree: **yes** (edit `{info['file']}` directly)")
    else:
        lines.append("- File present in working tree: **NO - the secret lives only "
                     "in git history. Do NOT try to open/edit the file.**")
    if info.get("secret_commits"):
        lines.append("- Commits containing this exact secret content "
                     "(verified via `git log -S`):")
        for c in info["secret_commits"]:
            lines.append(f"  - `{c}`")
    elif info.get("commits"):
        lines.append("- Commits that touched this file (secret is among their "
                     "changes - verify with `git show <hash>`):")
        for c in info["commits"][:6]:
            pushed = "pushed" if c.get("pushed") else "local only"
            lines.append(f"  - `{c['short']}` {c['date']} {c['subject'][:60]} ({pushed})")
    branch = info.get("branch")
    if branch:
        pushed = "PUSHED to origin - history rewrite requires force-push" \
            if info.get("branch_pushed") else "local only - safe to rewrite history"
        lines.append(f"- Branch `{branch}`: {pushed}")
    if info.get("remote"):
        lines.append(f"- Remote: `{info['remote']}`")
    lines.append("- gitleaks will keep flagging this until the secret is gone "
                 "from BOTH the working tree and git history.")
    fr = info.get("filter_repo_available")
    bfg = info.get("bfg_available")
    if fr or bfg:
        tool = "git filter-repo" if fr else "BFG Repo-Cleaner"
        lines.append(f"- Available history-rewrite tool: **{tool}**")
    else:
        lines.append("- No history-rewrite tool found. Install one: "
                     "`brew install git-filter-repo` (or `brew install bfg`).")
    return "\n".join(lines)
