"""Generate REMEDIATION_PLAN.md - a prioritized fix plan with imperative
AI directives that the Cursor agent can execute directly.

Each directive carries pre-investigated context (recon) so the agent does not
need to discover git state, file existence or verification mechanics itself.
"""
from pathlib import Path

from gatekeeper.core.recon import secret_recon, format_secret_context

CATEGORY_DIRECTIVES = {
    "sca": (
        "1. Update the affected dependency to the suggested fixed version.\n"
        "2. Run the project's lockfile update command (npm/pip/swift build resolve...).\n"
        "3. Run the project's tests to confirm nothing breaks."
    ),
    "sast": (
        "1. Read the flagged code and understand the vulnerability class.\n"
        "2. Apply the secure pattern (sanitize/validate input, use parameterized APIs, add checks).\n"
        "3. Keep behavior intact; refactor minimally.\n"
        "4. Add or adjust a test covering the insecure case if a test suite exists."
    ),
    "iac": (
        "1. Apply the secure configuration suggested for the misconfiguration.\n"
        "2. Keep infrastructure behavior unchanged otherwise.\n"
        "3. Validate the file syntax (docker compose config / terraform validate) if available."
    ),
    "dast": (
        "1. Locate the endpoint/behavior flagged.\n"
        "2. Apply the OWASP-recommended fix server-side.\n"
        "3. Confirm with a manual request that the issue no longer reproduces."
    ),
}

SECRET_DIRECTIVES_PUSHED = """1. Rotate/revoke the credential at the provider FIRST (removal alone is not enough).
2. If the file exists in the working tree: remove the secret from it and load
   the value from a build setting / environment variable / secrets manager
   instead. Do NOT hardcode a replacement value.
   If the file no longer exists (secret is history-only), skip this step.
3. Rewrite history so gitleaks stops flagging it:
   ```bash
   git filter-repo --invert-paths --path <FILE> --force
   ```
   (or use BFG if installed). Then re-add the cleaned file and commit.
4. Force-push the rewritten branch: `git push --force-with-lease origin <branch>`.
5. Tell the user to re-clone or `git pull --rebase` on every machine that has
   this repository, and to verify the new credential was never committed."""

SECRET_DIRECTIVES_LOCAL = """1. Rotate/revoke the credential at the provider FIRST (removal alone is not enough).
2. If the file exists in the working tree: remove the secret from it and load
   the value from a build setting / environment variable / secrets manager.
   If the file no longer exists, skip straight to step 3 - the fix is purely
   a history rewrite.
3. The branch was never pushed - you can rewrite history safely:
   ```bash
   git filter-repo --invert-paths --path <FILE> --force
   ```
   or, if the secret was added in an unpushed commit, amend/rebase it out.
4. Do NOT push the branch until the history rewrite is done."""

ACCEPTANCE_BY_CATEGORY = {
    "secrets": "The secret no longer appears in source, git history or the gitleaks scan output; the credential has been rotated.",
    "sca": "The dependency is at (or above) the fixed version in the lockfile/manifest.",
    "sast": "The flagged pattern is gone and equivalent secure behavior is in place.",
    "iac": "The misconfiguration no longer appears in the config file.",
    "dast": "The alert no longer fires against the target URL.",
}


def _location(f):
    if not f.get("file"):
        return "n/a"
    return f"{f['file']}:{f['line']}" if f.get("line") else f["file"]


def _secret_directives(f: dict) -> str:
    target = f.get("_recon") or {}
    return SECRET_DIRECTIVES_PUSHED if target.get("branch_pushed") \
        else SECRET_DIRECTIVES_LOCAL


def remediation_markdown(result: dict, gatekeeper_path: str = "gatekeeper") -> str:
    findings = result["findings"]
    fixable = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]

    # Pre-investigate secrets once (git operations are expensive).
    recons = {}
    for f in findings:
        if f.get("category") == "secrets" and f.get("_recon") is None:
            recons[id(f)] = secret_recon(result["target"], f)
            f["_recon"] = recons[id(f)]

    lines = [
        "# Remediation Plan (AI Directives)",
        "",
        f"**Target:** `{result['target']}`  |  **Scan:** {result['timestamp']}",
        "",
        "> This file contains step-by-step directives for an AI coding agent",
        "> (e.g. Cursor). All investigation has already been done: git history,",
        "> file existence and verification mechanics are listed per finding.",
        "> Execute the directives in order. Do NOT skip the final verification.",
        "> Do NOT commit any secret you find - rotate it.",
        "",
        "## Priority order",
        "",
        "1. CRITICAL findings first (secrets first, then SAST, then SCA).",
        "2. HIGH findings.",
        "3. MEDIUM findings.",
        "4. LOW/INFO findings are optional - fix only if trivial.",
        "",
        f"## Directives ({len(fixable)} actionable findings)",
        "",
    ]

    if not fixable:
        lines.append("No actionable findings. Run the verification step to confirm.")

    for i, f in enumerate(fixable, 1):
        category = f.get("category", "sast")
        if category == "secrets":
            steps = _secret_directives(f)
        else:
            steps = CATEGORY_DIRECTIVES.get(category, CATEGORY_DIRECTIVES["sast"])
        acceptance = ACCEPTANCE_BY_CATEGORY.get(category, "Finding no longer reported by the scan.")
        location = _location(f)
        lines += [
            f"## {i}. [{f['severity']}] {f['title']}",
            "",
            f"- **ID:** `{f.get('id', '')}`",
            f"- **Tool:** {f['tool']} ({category})",
            f"- **Where:** `{location}`",
            f"- **Risk score:** {f.get('risk_score', 'n/a')}/100",
        ]
        if f.get("cvss") is not None:
            lines.append(f"- **CVSS:** {f['cvss']}/10")
        if f.get("cwe"):
            owasp = f" | **OWASP:** {f['owasp']}" if f.get("owasp") else ""
            lines.append(f"- **CWE:** {f['cwe']}{owasp}")
        if f.get("package"):
            lines.append(f"- **Package:** `{f['package']}`")
        if f.get("introduced_via"):
            lines.append(f"- **Introduced via:** {' -> '.join(f['introduced_via'])}")
        lines += [
            f"- **Why it matters:** {f.get('description', '')}",
            "",
        ]

        if category == "secrets":
            lines += [
                "**Pre-investigated context (do not re-investigate):**",
                "",
                format_secret_context(f.get("_recon") or {}),
                "",
            ]
        if f.get("code_snippet"):
            lines += ["**Current code:**", "", "```", f["code_snippet"], "```", ""]

        lines += [
            "**Directives:**",
            "",
            steps,
            "",
            "**Acceptance criteria:** " + acceptance,
            "",
            "---",
            "",
        ]

    lines += [
        "## Final verification (mandatory)",
        "",
        "After applying all fixes above:",
        "",
        "1. Run:",
        "",
        "```bash",
        f"{gatekeeper_path} verify {result['target']}",
        "```",
        "",
        "2. How verification works: it re-runs every scanner and diffs against",
        "   the previous baseline scan. gitleaks scans BOTH the working tree and",
        "   full git history - a secret fixed in code but still in history will",
        "   keep verification red.",
        "3. If the command exits non-zero, read the remaining findings and",
        "   continue fixing. Repeat until it exits 0.",
        "4. Only then report completion. Summarize: findings fixed, files changed,",
        "   and any findings intentionally left open (with justification).",
        "",
    ]
    return "\n".join(lines)


def write_remediation(result: dict, out_dir: Path, gatekeeper_path: str = "gatekeeper"):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "REMEDIATION_PLAN.md").write_text(
        remediation_markdown(result, gatekeeper_path)
    )
