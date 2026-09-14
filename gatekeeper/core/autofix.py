"""Closed-loop SCA autofix: bump vulnerable dependencies, verify, open a PR.

Gatekeeper applies the mechanical fixes itself (manifest + lockfile update via
the ecosystem's CLI), re-runs the verification scan, and only then opens a
draft PR via gh. Anything non-mechanical is left to the AI plan - this module
only touches dependency bumps where automation is safe and reversible.

Usage:  gatekeeper fix <path> [--max N] [--no-pr]
"""
import re
import subprocess
from pathlib import Path

from gatekeeper.core import gh as gh_mod
from gatekeeper.core.runner import run_scan


def _run(cmd, cwd, timeout=600):
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def _parse_pkg(package: str):
    """'name@1.2.3' -> ('name', '1.2.3'); handles scoped npm '@a/b@1.2.3'."""
    if package.startswith("@"):
        rest = package[1:]
        if "@" in rest:
            name, ver = rest.rsplit("@", 1)
            return "@" + name, ver
        return package, ""
    if "@" in package:
        name, ver = package.rsplit("@", 1)
        return name, ver
    return package, ""


def sca_findings(summary: dict, max_fixes: int) -> list:
    """Fixable SCA findings with a known fixed version, sorted by risk."""
    out = []
    for f in summary.get("findings", []):
        if f.get("category") != "sca":
            continue
        if f.get("status") in ("ignored", "snoozed", "solved"):
            continue
        pkg = f.get("package") or ""
        name, _installed = _parse_pkg(pkg)
        fix = _fixed_version_from_finding(f)
        if name and fix:
            out.append({"finding": f, "name": name, "fix": fix,
                        "title": f.get("title", "")})
        if len(out) >= max_fixes:
            break
    return out


def _fixed_version_from_finding(f: dict) -> str:
    text = f.get("remediation_hint", "") or ""
    m = re.search(r"[Uu]pgrade \S+ to (\d[^\s,;)]*)", text)
    if m:
        return m.group(1)
    m = re.search(r"suggested: (\d[^\s,;)]*)", text)
    if m:
        return m.group(1)
    return ""


def _upgrade_js(target: Path, name: str, fix: str) -> tuple[bool, str]:
    """Pick the lockfile-aware package manager present in the repo."""
    if (target / "pnpm-lock.yaml").exists():
        cmd = ["pnpm", "add", f"{name}@{fix}"]
    elif (target / "yarn.lock").exists():
        cmd = ["yarn", "add", f"{name}@{fix}"]
    else:
        cmd = ["npm", "install", f"{name}@{fix}"]
    code, out, err = _run(cmd, target, timeout=900)
    ok = code == 0
    detail = (err or out).strip().splitlines()
    return ok, (detail[-1][:160] if detail else ("" if ok else f"exit {code}"))


def _upgrade_python(target: Path, name: str, fix: str) -> tuple[bool, str]:
    """Update requirements*.txt pins directly (pip cannot edit them in place)."""
    changed_any = False
    for req in sorted(target.rglob("requirements*.txt")):
        try:
            lines = req.read_text().splitlines(keepends=True)
        except OSError:
            continue
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            pkg = re.split(r"[<>=~!\[; ]", stripped, maxsplit=1)[0].strip()
            if pkg.lower() == name.lower():
                lines[i] = re.sub(r"^[^#;\n]*", f"{name}=={fix}", ln)
                req.write_text("".join(lines))
                changed_any = True
                break
    if not changed_any:
        return False, "package not found in requirements*.txt"
    return True, f"pinned {name}=={fix} in requirements"


def apply_fixes(target: str, summary: dict, max_fixes: int = 20) -> dict:
    """Apply dependency bumps. Returns a report dict; never raises."""
    target = Path(target)
    fixes = sca_findings(summary, max_fixes)
    applied, failed = [], []

    for item in fixes:
        name, fix = item["name"], item["fix"]
        f = item["finding"]
        e_title = item.get("title", f.get("title", ""))
        file = f.get("file", "") or ""
        is_js = bool((target / "package.json").exists() or
                     "package-lock" in file or "yarn.lock" in file or
                     "pnpm-lock" in file or "package.json" in file)
        is_py = "requirements" in file or (not is_js and
                                           (target / "requirements.txt").exists())
        if is_js:
            ok, note = _upgrade_js(target, name, fix)
        elif is_py:
            ok, note = _upgrade_python(target, name, fix)
        else:
            ok, note = False, "unsupported ecosystem for autofix"
        entry = {"package": f"{name}@{fix}", "title": e_title, "ok": ok,
                 "note": note}
        (applied if ok else failed).append(entry)

    return {"applied": applied, "failed": failed}


def autofix_loop(target: str, max_fixes: int = 20, open_pr: bool = True) -> int:
    """fix -> verify -> (optional) PR. Exit 0 when the loop leaves no new
    HIGH/CRITICAL findings."""
    target_path = Path(target).expanduser().resolve()

    print(f"Gatekeeper autofix on {target_path}")
    result, scan_dir = run_scan(target_path, progress_cb=_progress())
    summary = result.to_dict()

    print("\nApplying SCA fixes...")
    report = apply_fixes(target, summary)
    for e in report["applied"]:
        print(f"  [OK]   {e['package']}  ({e['title'][:60]})")
    for e in report["failed"]:
        print(f"  [FAIL] {e['package']}  {e['note'][:80]}")
    if not report["applied"]:
        print("Nothing applied automatically - use the AI plan for code fixes.")

    if report["applied"]:
        print("\nRe-scanning to verify the fixes...")
        result, scan_dir = run_scan(target_path, progress_cb=_progress())
        summary = result.to_dict()

    if open_pr and report["applied"] and gh_mod.gh_available(target_path):
        print("\nOpening fix PR...")
        try:
            pr = _open_autofix_pr(target_path, report, summary)
            print(f"  PR: {pr['url']}")
        except gh_mod.GhError as exc:
            print(f"  PR failed: {exc}")

    blocking = [f for f in summary["findings"]
                if f["severity"] in ("CRITICAL", "HIGH")]
    print(f"\nRemaining HIGH/CRITICAL findings: {len(blocking)}")
    print(f"Full report: {scan_dir}")
    return 1 if blocking else 0


def _progress():
    def cb(event, **kw):
        if event == "tool_start":
            print(f"-> {kw['tool']} ...", flush=True)
        elif event == "tool_done":
            if kw.get("note"):
                print(f"   {kw['note']}")
    return cb


def _open_autofix_pr(target: Path, report: dict, summary: dict) -> dict:
    branch = f"{gh_mod.BRANCH_PREFIX}/autofix-deps"
    slug = gh_mod.repo_slug(target)

    def git(*args):
        code, _out, err = _run(["git", *args], target, timeout=120)
        if code != 0:
            raise gh_mod.GhError(f"git {' '.join(args[:2])}: "
                                 f"{(err or '').strip()[:160]}")

    git("checkout", "-b", branch)
    try:
        git("add", "-A")
        git("commit", "-m", f"gatekeeper: autofix {len(report['applied'])} "
                             f"vulnerable dependencies")
        _run(["git", "push", "-u", "origin", branch], target, timeout=120)
        bumps = "\n".join(f"- `{e['package']}` ({e['title'][:80]})"
                          for e in report["applied"])
        body = (
            "## Gatekeeper autofix (dependency bumps)\n\n"
            f"Target: `{target}` | Repo: `{slug}`\n\n"
            "### Upgrades applied\n\n" + bumps +
            "\n\n### Verification\n\n"
            "Re-scan completed after the bumps; see the Gatekeeper report for "
            "the remaining findings.\n"
        )
        out = gh_mod._run(["gh", "pr", "create", "--title",
                           "[Gatekeeper] Autofix: dependency security bumps",
                           "--body", body, "--draft"], str(target))
        return {"url": out.strip().splitlines()[-1], "branch": branch}
    finally:
        _run(["git", "checkout", "-"], target, timeout=60)
