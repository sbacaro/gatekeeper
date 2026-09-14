"""Diff-aware scanning for CI: restrict findings to what a change introduced.

Compares the current scan against a baseline (a previous summary.json), keyed
by the stable finding fingerprint (tool + category + file + title) instead of
file:line, so line drift does not resurrect old findings as "new".
"""
import json
from pathlib import Path


def fingerprint_key(f: dict) -> str:
    """Stable identity across scans: line-independent where possible."""
    fp = f.get("fingerprint") or ""
    if fp:
        # fingerprints embed line; strip it -> tool:category:file:title
        parts = fp.split(":")
        if len(parts) >= 5:
            return ":".join(parts[:3]) + ":" + ":".join(parts[4:])
    return f"{f.get('category')}|{f.get('file')}|{(f.get('title') or '').lower()}"


def load_baseline(path) -> dict | None:
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def diff_findings(baseline: dict, current_findings: list) -> dict:
    """Returns {'new': [...], 'fixed': [...], 'remaining': [...]}.

    'new' findings are those whose fingerprint is not in the baseline and that
    exist in files touched by the change when `changed_files` is provided.
    """
    base_map = {fingerprint_key(f): f for f in baseline.get("findings", [])}
    cur_map = {fingerprint_key(f): f for f in current_findings}

    new = [f for k, f in cur_map.items() if k not in base_map]
    fixed = [f for k, f in base_map.items() if k not in cur_map]
    remaining = [f for k, f in cur_map.items() if k in base_map]
    return {"new": new, "fixed": fixed, "remaining": remaining}


def restrict_to_changed(findings: list, changed_files: list) -> list:
    """Keep only findings located in one of changed_files (empty -> unchanged)."""
    if not changed_files:
        return findings
    changed = set(changed_files)
    out = []
    for f in findings:
        file = (f.get("file") or "").replace("\\", "/")
        # SCA findings report lockfile paths; keep them if any changed file
        # is a dependency manifest in the same directory.
        base = file.rsplit("/", 1)[0] if "/" in file else ""
        if file in changed or (f.get("category") == "sca" and
                               any(cf.rsplit("/", 1)[0] == base for cf in changed)):
            out.append(f)
    return out
