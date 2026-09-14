"""Scanner runners. Each function runs an external tool, writes raw JSON
into the scan directory and returns a list of normalized Finding objects.
"""
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from gatekeeper.core.models import Finding
from gatekeeper.core.detect import inventory
from gatekeeper.core.risk import cwe_of, owasp_of

SKIP_DIRS = {
    ".git", "node_modules", "reports", ".build", "DerivedData", "Pods",
    "__pycache__", ".venv", "venv", "dist", "build", ".next", ".cache",
}

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
GATEKEEPER_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep-security.yaml"


def _fingerprint(tool, category, file, line, title):
    return f"{tool}:{category}:{file}:{line}:{title}"


def _make_finding(tool, category, severity, file, line, title, description, hint, **extra):
    fp = _fingerprint(tool, category, str(file), int(line or 0), title)
    cwe = cwe_of(title) or cwe_of(description)
    finding = Finding(
        id=fp[:8] + "-" + uuid.uuid4().hex[:8],
        severity=severity,
        tool=tool,
        category=category,
        file=str(file),
        line=int(line or 0),
        title=title,
        description=description,
        remediation_hint=hint,
        fingerprint=fp,
        cwe=cwe,
        owasp=owasp_of(cwe),
    )
    for k, v in extra.items():
        if v is not None and v != "" and v != []:
            setattr(finding, k, v)
    return finding


def _run(cmd, cwd=None, timeout=900):
    """Run a command, capture output, return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]} timed out after {timeout}s"


def _save_raw(raw_dir, tool, data):
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / f"{tool}.json"
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def _parse_json(stdout):
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------- Semgrep ----

def run_semgrep(target, raw_dir, progress_cb=None, **_):
    target = Path(target)
    # Chunk by top-level directories for real file-count progress.
    subdirs, loose_files = [], []
    try:
        for entry in sorted(target.iterdir()):
            if entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            if entry.is_dir():
                subdirs.append(entry)
            else:
                loose_files.append(entry)
    except OSError:
        pass
    chunks = subdirs + ([target] if loose_files else [])
    total_files = sum(inventory(c)["total_files"] for c in chunks) if chunks else 0
    scanned_files = 0

    findings = []
    saw_skip_note = None
    for i, chunk in enumerate(chunks, 1):
        inv = inventory(chunk)
        if progress_cb:
            progress_cb("tool_detail", tool="semgrep",
                        detail=f"{inv['total_files']}/{total_files} files - {chunk.name}",
                        pct=int((scanned_files / total_files) * 100) if total_files else 0,
                        files_done=scanned_files, files_total=total_files)
        custom_rules = GATEKEEPER_RULES.exists()
        config_args = ["--config", str(GATEKEEPER_RULES)] if custom_rules else \
            ["--config", "auto"]
        cmd = ["semgrep", "scan", "--json", "--quiet"] + config_args + [str(chunk)]
        code, stdout, stderr = _run(cmd, timeout=1200)
        data = _parse_json(stdout)
        if data is None:
            if code == 127:
                return [], "skipped (semgrep not installed)"
            # A single chunk failing should not kill the scan; record and move on.
            saw_skip_note = f"error: {stderr.strip()[:160] or 'invalid JSON output'}"
            scanned_files += inv["total_files"]
            continue
        _save_raw(raw_dir, f"semgrep-{i}", data)
        scanned_files += inv["total_files"]
        if progress_cb:
            progress_cb("tool_detail", tool="semgrep",
                        detail=f"{scanned_files}/{total_files} files - {chunk.name}",
                        pct=int((scanned_files / total_files) * 100) if total_files else 100,
                        files_done=scanned_files, files_total=total_files)
        for result in data.get("results", []):
            check_id = result.get("check_id", "semgrep.unknown")
            # Strip registry prefixes for readable titles (rules.semgrep.gatekeeper.x -> x)
            short_id = check_id.split(".")[-1] if check_id.count(".") >= 2 else check_id
            extra = result.get("extra", {})
            sev_raw = str(extra.get("severity", "INFO")).upper()
            severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(sev_raw, "MEDIUM")
            path = result.get("path", "")
            line = result.get("start", {}).get("line", 0)
            title = (extra.get("message", "") or short_id)[:120]
            description = f"Semgrep rule: {check_id}\n{extra.get('message', '')}"
            hint = extra.get("fix", "") or (
                "Review the flagged code against the Semgrep rule above and apply "
                "the secure pattern recommended by the rule documentation."
            )
            findings.append(_make_finding(
                "semgrep", "sast", severity, path, line, title, description, hint
            ))
    note = saw_skip_note if (saw_skip_note and not findings) else (saw_skip_note or None)
    return findings, note


# ------------------------------------------------------------------ Trivy ----

_TRIVY_SEV = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "UNKNOWN": "LOW",
}


def _trivy_cvss(vuln: dict) -> float | None:
    cvss_data = vuln.get("CVSS") or {}
    scores = []
    for vendor in cvss_data.values():
        for key in ("V3Score", "Score"):
            v = vendor.get(key)
            if isinstance(v, (int, float)):
                scores.append(float(v))
    return max(scores) if scores else None


def _trivy_chain(vuln: dict) -> list:
    """Transitive dependency path when Trivy provides it (root pkg -> ... -> vulnerable pkg)."""
    chain = []
    for ref in vuln.get("Custom", {}).get("trivy", {}).get("Sources", []) or []:
        name = ref.get("Name")
        if name:
            chain.append(name)
    return chain


def run_trivy(target, raw_dir, **_):
    cmd = [
        "trivy", "fs", "--scanners", "vuln,misconfig,secret",
        "--format", "json", "--quiet",
        str(target),
    ]
    code, stdout, stderr = _run(cmd, timeout=1200)
    data = _parse_json(stdout)
    if data is None:
        if code == 127:
            return [], "skipped (trivy not installed)"
        return [], f"error: {stderr.strip()[:200] or 'invalid JSON output'}"
    _save_raw(raw_dir, "trivy", data)

    findings = []
    for result in data.get("Results", []):
        tpath = result.get("Target", "")
        rclass = result.get("Class", "")

        if rclass == "secret":
            for secret in result.get("Secrets", []):
                findings.append(_make_finding(
                    "trivy", "secrets",
                    _TRIVY_SEV.get(secret.get("Severity", "HIGH"), "HIGH"),
                    tpath, secret.get("StartLine", 0),
                    f"Secret detected: {secret.get('Title', 'credential')}",
                    secret.get("Match", "")[:200],
                    "Remove the secret from source, add the file pattern to "
                    ".gitignore, and rotate the exposed credential immediately.",
                ))

        for vuln in result.get("Vulnerabilities", None) or []:
            pkg = vuln.get("PkgName", "unknown")
            vid = vuln.get("VulnerabilityID", "CVE")
            cvss = _trivy_cvss(vuln)
            chain = _trivy_chain(vuln)
            pkg_ver = f"{pkg}@{vuln.get('InstalledVersion', '')}"
            findings.append(_make_finding(
                "trivy", "sca",
                _TRIVY_SEV.get(vuln.get("Severity", "UNKNOWN"), "LOW"),
                tpath, 0,
                f"{vid} in {pkg}",
                vuln.get("Title", ""),
                f"Upgrade {pkg} to a fixed version "
                f"(suggested: {vuln.get('FixedVersion', 'latest secure')}).",
                cvss=cvss,
                introduced_via=chain,
                package=pkg_ver,
            ))

        for mis in result.get("Misconfigurations", None) or []:
            sev = _TRIVY_SEV.get(mis.get("Severity", "UNKNOWN"), "LOW")
            findings.append(_make_finding(
                "trivy", "iac", sev, tpath, 0,
                f"{mis.get('ID', 'misconfig')}: {mis.get('Title', '')}",
                mis.get("Description", "")[:400],
                (mis.get("Resolution", "") or
                 "Apply the fix described in the Trivy misconfiguration reference."),
            ))
    return findings, None


# --------------------------------------------------------------- Gitleaks ----

_GITLEAKS_SEV = "HIGH"


def run_gitleaks(target, raw_dir, progress_cb=None, **_):
    """Git history (if repo) + working tree scanned in directory chunks so the
    UI can show real progress (chunk k of N, current folder)."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    report_path = raw_dir / "gitleaks.json"
    target = Path(target)
    has_git = (target / ".git").exists()

    def report_cb(detail, pct):
        if progress_cb:
            progress_cb("tool_detail", tool="gitleaks", detail=detail, pct=pct)

    base_cmd = ["gitleaks", "--report-format", "json", "--redact=100",
                "--exit-code", "0", "--log-level", "error"]
    all_leaks = []
    seen = set()

    def collect(rpt_path):
        try:
            leaks = json.loads(Path(rpt_path).read_text())
        except (json.JSONDecodeError, OSError):
            leaks = []
        for leak in leaks:
            key = (leak.get("RuleID"), leak.get("File"), leak.get("StartLine"),
                   leak.get("Commit"))
            if key not in seen:
                seen.add(key)
                all_leaks.append(leak)

    def collect(rpt_path):
        try:
            leaks = json.loads(Path(rpt_path).read_text())
        except (json.JSONDecodeError, OSError):
            leaks = []
        for leak in leaks:
            key = (leak.get("RuleID"), leak.get("File"), leak.get("StartLine"),
                   leak.get("Commit"))
            if key not in seen:
                seen.add(key)
                all_leaks.append(leak)

    def run_one(cmd, rpt_path):
        code, _stdout, stderr = _run(cmd, timeout=900)
        if code == 127:
            return "skipped (gitleaks not installed)"
        if code not in (0, 1):
            return f"error: {(stderr or '').strip()[:200]}"
        # gitleaks exits 1 both for "leaks found" and for fatal errors such as
        # an unwritable report path. Only trust the result if the report file
        # was actually produced; otherwise surface the stderr.
        if not Path(rpt_path).exists():
            detail = (stderr or "").strip().splitlines()
            msg = next((ln for ln in detail if "FTL" in ln or "error" in ln.lower()),
                       detail[-1] if detail else "no report produced")
            return f"error: gitleaks produced no report ({msg[:150]})"
        return None

    if has_git:
        report_cb("git history", 5)
        err = run_one(["gitleaks", "git", str(target),
                       "--report-path", str(report_path)] + base_cmd[1:],
                      report_path)
        if err:
            return [], err
        collect(report_path)

    # Chunk the working tree by top-level directories -> real progress %.
    subdirs, loose = [], False
    try:
        for entry in sorted(target.iterdir()):
            if entry.name in SKIP_DIRS or entry.name.startswith("."):
                continue
            if entry.is_dir():
                subdirs.append(entry)
            else:
                loose = True
    except OSError:
        pass

    chunks = subdirs + ([target] if loose else [])
    total = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        base = 10 if has_git else 0
        pct = base + int((i / total) * (100 - base)) if total else 100
        report_cb(f"{chunk.name}/ ({i}/{total})", pct)
        rpt = raw_dir / f"gitleaks-chunk-{i}.json"
        cmd = ["gitleaks", "dir", str(chunk), "--max-target-megabytes", "50",
               "--report-path", str(rpt)] + base_cmd[1:]
        err = run_one(cmd, rpt)
        if err:
            return [], err
        collect(rpt)
    data = all_leaks

    findings = []
    for leak in data:
        findings.append(_make_finding(
            "gitleaks", "secrets", _GITLEAKS_SEV,
            leak.get("File", ""), leak.get("StartLine", 0),
            f"Secret: {leak.get('RuleID', 'credential')}",
            f"Commit {leak.get('Commit', '')[:12]}: "
            f"{leak.get('Secret', '')[:6]}... (redacted)",
            "Remove the secret from the source and git history "
            "(git filter-repo / BFG), then rotate the credential immediately.",
        ))
    return findings, None


# ------------------------------------------------------------ OSV-Scanner ----

def _osv_cvss(vuln: dict) -> float | None:
    for sev_entry in vuln.get("severity", []):
        score = sev_entry.get("score", "")
        m = re.search(r"CVSS:3\.[01]/.*", str(score))
        if m:
            parsed = _parse_cvss_v3_base(m.group(0))
            if parsed is not None:
                return parsed
    return None


def _osv_severity(vuln: dict, fallback: str) -> str:
    """Derive severity from CVSS vector when present; keep heuristic fallback."""
    for sev_entry in vuln.get("severity", []):
        m = re.search(r"CVSS:3\.[01]/", str(sev_entry.get("score", "")))
        if sev_entry.get("type") == "CVSS_V3" and m:
            cvss = _osv_cvss(vuln)
            if cvss is None:
                break
            if cvss >= 9.0:
                return "CRITICAL"
            if cvss >= 7.0:
                return "HIGH"
            if cvss >= 4.0:
                return "MEDIUM"
            return "LOW"
    return fallback


import math


def _roundup(x: float) -> float:
    """CVSS v3.1 specification rounding: smallest number with one decimal
    that is >= x (rounds up at the smallest significant digit)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _parse_cvss_v3_base(vector: str) -> float | None:
    """Minimal CVSS v3.0/3.1 base-score computation from a vector string."""
    try:
        metrics = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV"))
        ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC"))
        ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI"))
        pr_val = {"N": 0.85, "L": 0.68, "H": 0.5}.get(metrics.get("PR"))
        if not (av and ac and ui and pr_val):
            return None
        scope_changed = metrics.get("S") == "C"
        exploitability = 8.22 * av * ac * pr_val * ui
        w = {"H": 0.56, "L": 0.22, "N": 0}
        c = w.get(metrics.get("C", "N"), 0)
        i = w.get(metrics.get("I", "N"), 0)
        a = w.get(metrics.get("A", "N"), 0)
        isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
            if isc <= 0:
                return 0.0
            return _roundup(min(1.08 * (_roundup(isc) + exploitability), 10.0))
        isc = 6.42 * isc_base
        if isc <= 0:
            return 0.0
        return _roundup(_roundup(isc) + exploitability)
    except Exception:
        return None


def run_osv(target, raw_dir, **_):
    # osv-scanner 2.x: `scan source <dir>`; 1.x: positional dir.
    cmd = ["osv-scanner", "scan", "source", "--format", "json", str(target)]
    code, stdout, stderr = _run(cmd, timeout=900)
    data = _parse_json(stdout)
    if data is None:
        if code == 127:
            return [], "skipped (osv-scanner not installed)"
        # Try legacy 1.x syntax as fallback
        cmd = ["osv-scanner", "--json", str(target)]
        code, stdout, stderr = _run(cmd, timeout=900)
        data = _parse_json(stdout)
        if data is None:
            if code == 127:
                return [], "skipped (osv-scanner not installed)"
            if code == 128:
                return [], "skipped (no lockfiles found)"
            return [], f"error: {stderr.strip()[:200] or 'no parsable output'}"
    _save_raw(raw_dir, "osv-scanner", data)

    findings = []
    seen_cves = set()
    for result in data.get("results", []):
        source = result.get("source", {}).get("path", "")
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            name = pkg_info.get("name", "unknown")
            version = pkg_info.get("version", "")
            for vuln in pkg.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "OSV")
                aliases = vuln.get("aliases", [])
                # Same CVE reported under PYSEC/GHSA/OSV ids: keep one entry per CVE.
                cve = next((a for a in [vuln_id] + aliases if a.startswith("CVE-")), None)
                dedupe_key = (cve or vuln_id, name, source)
                if dedupe_key in seen_cves:
                    continue
                seen_cves.add(dedupe_key)
                alias_str = ",".join(aliases[:2])
                sev = "HIGH"
                for sev_entry in vuln.get("severity", []):
                    if sev_entry.get("type") == "CVSS_V3" and "9." in sev_entry.get("score", ""):
                        sev = "CRITICAL"
                        break
                fix_versions = []
                for aff in vuln.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fix_versions.append(ev["fixed"])
                fix = fix_versions[0] if fix_versions else "latest secure release"
                cvss = _osv_cvss(vuln)
                sev = _osv_severity(vuln, sev)
                findings.append(_make_finding(
                    "osv-scanner", "sca", sev, source, 0,
                    f"{cve or vuln_id} ({alias_str}) in {name}@{version}",
                    vuln.get("summary", "") or vuln.get("details", "")[:300],
                    f"Upgrade {name} to {fix} or later.",
                    cvss=cvss,
                    package=f"{name}@{version}",
                ))
    return findings, None


# -------------------------------------------------------------------- ZAP ----

def run_zap(target, raw_dir, dast_url=None, **_):
    if not dast_url:
        return [], None
    if not shutil.which("docker"):
        return [], "skipped (docker not available for ZAP DAST)"
    report_path = raw_dir / "zap.json"
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{raw_dir.absolute()}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py", "-t", dast_url, "-J", "zap.json", "-I",
    ]
    code, stdout, stderr = _run(cmd, timeout=1800)
    try:
        data = json.loads(report_path.read_text())
    except (json.JSONDecodeError, OSError):
        if code == 125:
            return [], f"error: {stderr.strip()[:200]}"
        return [], "error: ZAP produced no parsable report"

    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Medium (Medium)").upper()
            if "HIGH" in risk:
                severity = "HIGH"
            elif "CRITICAL" in risk:
                severity = "CRITICAL"
            elif "MEDIUM" in risk:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            instances = alert.get("instances", [])
            loc = instances[0].get("uri", "") if instances else dast_url
            findings.append(_make_finding(
                "zap", "dast", severity, loc, 0,
                alert.get("name", "ZAP alert"),
                alert.get("desc", "")[:400],
                alert.get("solution", "Apply the ZAP recommended solution."),
            ))
    return findings, None


# ------------------------------------------------------------------ MobSF ----

def run_mobsf(target, raw_dir, **_):
    """Delegates to the REST API integration in mobsf.py."""
    from mobsf import run_mobsf as _run_mobsf
    return _run_mobsf(target, raw_dir, **_)


# ---------------------------------------------------------------- Checkov ----

_CHECKOV_SEV = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "INFO": "INFO", "OFF": "INFO",
}


def run_checkov(target, raw_dir, **_):
    cmd = [
        "checkov", "-d", str(target), "--framework",
        "terraform,cloudformation,kubernetes,serverless,dockerfile,github_actions",
        "-o", "json", "--quiet", "--compact",
    ]
    code, stdout, stderr = _run(cmd, timeout=1200)
    data = _parse_json(stdout)
    if data is None:
        if code == 127:
            return [], "skipped (checkov not installed)"
        return [], f"error: {(stderr or '').strip()[:200] or 'invalid JSON output'}"
    if isinstance(data, dict):
        data = [data]
    _save_raw(raw_dir, "checkov", data)

    findings = []
    for report in data:
        for failed in report.get("results", {}).get("failed_checks", []) or []:
            # Community Checkov emits severity=None; map CKV rule classes to a
            # sensible default so ranking still works.
            sev = _CHECKOV_SEV.get(str(failed.get("severity") or "HIGH").upper(), "HIGH")
            evaluated = (failed.get("check_result") or {}).get("evaluated_keys") or []
            description = ("Evaluated: " + ", ".join(evaluated)) if evaluated \
                else str(failed.get("guideline", ""))[:300]
            findings.append(_make_finding(
                "checkov", "iac", sev,
                failed.get("file_path", "").lstrip("/"),
                failed.get("file_line_start") or failed.get("file_line_end") or 0,
                f"{failed.get('check_id', 'CKV')}: {failed.get('check_name', '')}",
                description,
                failed.get("guideline", "") or
                    "Apply the fix described in the Checkov guideline for this policy.",
            ))
    return findings, None


# ---------------------------------------------------------- Syft + Grype ----

def run_syft(target, raw_dir, **_):
    """Generate an SBOM (CycloneDX JSON) for the target directory."""
    cmd = ["syft", "scan", str(target), "-o", "cyclonedx-json"]
    code, stdout, stderr = _run(cmd, timeout=900)
    data = _parse_json(stdout)
    if data is None:
        if code == 127:
            return [], "skipped (syft not installed)"
        return [], f"error: {(stderr or '').strip()[:200] or 'invalid JSON output'}"
    _save_raw(raw_dir, "syft-sbom", data)
    # Syft itself does not emit findings - it produces the SBOM consumed by
    # Grype. Keep it silent in the report besides the artifact count.
    components = data.get("components", [])
    return [], f"SBOM generated ({len(components)} packages)"


def run_grype(target, raw_dir, progress_cb=None, **_):
    """Vulnerability scan of the Syft SBOM (falls back to dir scan)."""
    sbom_path = raw_dir / "syft-sbom.json"
    if sbom_path.exists():
        cmd = ["grype", "sbom:" + str(sbom_path), "-o", "json"]
    else:
        cmd = ["grype", "dir:" + str(target), "-o", "json"]
    code, stdout, stderr = _run(cmd, timeout=1200)
    data = _parse_json(stdout)
    if data is None:
        if code == 127:
            return [], "skipped (grype not installed)"
        return [], f"error: {(stderr or '').strip()[:200] or 'invalid JSON output'}"
    _save_raw(raw_dir, "grype", data)

    findings = []
    for m in data.get("matches", []):
        vuln = m.get("vulnerability", {}) or {}
        art = m.get("artifact", {}) or {}
        vid = vuln.get("id", "CVE")
        pkg = art.get("name", "unknown")
        version = art.get("version", "")
        sev_raw = str(vuln.get("severity", "Unknown")).upper()
        severity = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                    "LOW": "LOW", "NEGLIGIBLE": "INFO", "UNKNOWN": "LOW"}.get(sev_raw, "LOW")
        fix_versions = []
        for detail in m.get("match_details") or []:
            fix_v = ((detail.get("vulnerability") or {}).get("fix") or {}).get("versions") or []
            fix_versions.extend(fix_v)
        fix = fix_versions[0] if fix_versions else "latest secure release"
        cvss_entries = vuln.get("cvss") or []
        cvss = None
        cwe = ""
        for entry in cvss_entries:
            metrics = entry.get("metrics") or {}
            if isinstance(metrics.get("baseScore"), (int, float)):
                cvss = float(metrics["baseScore"])
            cwe_raw = entry.get("cwe") or ""
            if cwe_raw and not cwe:
                cwe = str(cwe_raw).split(",")[0].strip()
        chain = [(rel.get("dependency") or {}).get("name")
                 for rel in (m.get("match_details") or [])]
        chain = [c for c in chain if c]
        findings.append(_make_finding(
            "grype", "sca", severity,
            (art.get("locations") or [{}])[0].get("path", ""), 0,
            f"{vid} in {pkg}@{version}",
            (vuln.get("description", "") or "")[:300],
            f"Upgrade {pkg} to {fix} or later.",
            cvss=cvss,
            cwe=cwe if cwe.startswith("CWE") else "",
            package=f"{pkg}@{version}",
            introduced_via=chain,
        ))
    return findings, None


# ------------------------------------------------------------------ Nuclei ---

def run_nuclei(target, raw_dir, dast_url=None, **_):
    if not dast_url:
        return [], None
    cmd = ["nuclei", "-u", dast_url, "-json", "-silent", "-nc"]
    code, stdout, stderr = _run(cmd, timeout=1800)
    findings = []
    results = []
    for line in stdout.splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not results and code == 127:
        return [], "skipped (nuclei not installed)"
    if results:
        _save_raw(raw_dir, "nuclei", results)

    for r in results:
        sev_raw = str(r.get("info", {}).get("severity", "low")).upper()
        severity = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                    "LOW": "LOW", "INFO": "INFO"}.get(sev_raw, "LOW")
        info = r.get("info", {}) or {}
        cwe = ""
        tags = info.get("classification", {}) or {}
        cwes = tags.get("cwe-id") or []
        if isinstance(cwes, list) and cwes:
            cwe = str(cwes[0])
        findings.append(_make_finding(
            "nuclei", "dast", severity, r.get("matched-at", dast_url or ""), 0,
            f"{r.get('template-id', 'nuclei')}: {info.get('name', 'finding')}",
            info.get("description", "")[:400],
            info.get("remediation", "Apply the Nuclei template recommended fix."),
            cwe=cwe if cwe.startswith("CWE") else "",
        ))
    if not results:
        return [], "no Nuclei findings (or templates never ran - check connectivity)"
    return findings, None


# ---------------------------------------------------------------- GuardDog --

def run_guarddog(target, raw_dir, **_):
    """Scan PyPI/npm dependency manifests for known-malicious packages."""
    target = Path(target)
    found_pkgs = []  # (ecosystem, name, version)
    for req in target.rglob("requirements*.txt"):
        try:
            for ln in req.read_text(errors="replace").splitlines():
                ln = ln.strip()
                if not ln or ln.startswith(("#", "-")):
                    continue
                name = re.split(r"[<>=~!\[; ]", ln, 1)[0].strip()
                if name:
                    found_pkgs.append(("pypi", name))
        except OSError:
            continue
    for pkgjson in target.rglob("package.json"):
        if "node_modules" in str(pkgjson):
            continue
        try:
            deps = json.loads(pkgjson.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for group in ("dependencies", "devDependencies"):
            for name in (deps.get(group) or {}):
                found_pkgs.append(("npm", name))

    if not found_pkgs:
        return [], None
    if not shutil.which("guarddog"):
        return [], "skipped (guarddog not installed)"

    findings = []
    for eco, name in sorted(set(found_pkgs)):
        cmd = ["guarddog", eco + "-scan", name, "--output-format", "json"]
        code, stdout, stderr = _run(cmd, timeout=300)
        data = _parse_json(stdout)
        if data is None:
            continue
        results = data.get(name, {}).get("results", [])
        for r in results:
            sev = "HIGH" if r.get("severity", "").upper() in ("CRITICAL", "HIGH") else "MEDIUM"
            findings.append(_make_finding(
                "guarddog", "sca", sev, "", 0,
                f"Malicious package: {name} ({eco})",
                f"{r.get('rule', '')}: {str(r.get('description', ''))[:250]}",
                f"Pin {name} to a trusted version or replace it; audit what it "
                "may have executed in your environment.",
            ))
    return findings, None


TOOL_RUNNERS = {
    "semgrep": run_semgrep,
    "trivy": run_trivy,
    "gitleaks": run_gitleaks,
    "osv-scanner": run_osv,
    "checkov": run_checkov,
    "syft": run_syft,
    "grype": run_grype,
    "nuclei": run_nuclei,
    "guarddog": run_guarddog,
    "zap": run_zap,
    "mobsf": run_mobsf,
}
