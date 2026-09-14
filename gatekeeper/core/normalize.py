"""Merge findings from all scanners, dedupe, sort and build the ScanResult."""
import re

from gatekeeper.core import threat
from gatekeeper.core.models import ScanResult
from gatekeeper.core.risk import compute_risk

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _dedupe_key(f):
    return (f.category, f.file, f.line, f.title.lower())


def _cve_of(text):
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def merge_findings(all_findings):
    """Dedupe findings reported by multiple tools, keeping the highest severity."""
    SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    by_key = {}
    for f in all_findings:
        key = _dedupe_key(f)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
        else:
            # Keep the more severe one; prefer the more specific tool
            # (gitleaks over trivy for secrets)
            if SEV_RANK.get(f.severity, 0) > SEV_RANK.get(existing.severity, 0):
                merged = f
            else:
                merged = existing
            # note all tools that reported it
            tools = {existing.tool, f.tool}
            merged.tool = "+".join(sorted(tools)) if len(tools) > 1 else merged.tool
            by_key[key] = merged

    # Cross-tool dedupe for dependency CVEs: trivy + osv-scanner report the same
    # advisory with different titles. Collapse to one entry per (cve, file).
    cve_seen = {}
    to_remove = []
    for key, f in by_key.items():
        if f.category != "sca":
            continue
        cve = _cve_of(f.title)
        if not cve:
            continue
        ckey = (cve, f.file.split("/")[-1] if f.file else f.file)
        prev = cve_seen.get(ckey)
        if prev is None:
            cve_seen[ckey] = f
        else:
            winner, loser = (
                (f, prev) if SEV_RANK.get(f.severity, 0) > SEV_RANK.get(prev.severity, 0)
                else (prev, f)
            )
            tools = {winner.tool, loser.tool}
            winner.tool = "+".join(sorted(tools)) if len(tools) > 1 else winner.tool
            cve_seen[ckey] = winner
            to_remove.append(key)
    for key in to_remove:
        by_key.pop(key, None)

    return list(by_key.values())


def enrich_findings(findings):
    """Attach threat intel (KEV/EPSS) and risk scores, then sort by risk."""
    as_dicts = [f.to_dict() for f in findings]
    try:
        kev = threat.load_kev()
        epss = threat.load_epss()
    except Exception:
        kev, epss = {}, {}
    threat.enrich_with_threat_intel(as_dicts, kev, epss)

    by_id = {}
    for f in findings:
        by_id[f.id] = f
    enriched = []
    for d in as_dicts:
        original = by_id.get(d["id"])
        if original is None:
            continue
        for key in ("kev", "kev_date", "ransomware", "epss"):
            if key in d:
                setattr(original, key, d[key])
        original.risk_score = compute_risk(d)
        enriched.append(original)

    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    enriched.sort(
        key=lambda f: (-f.risk_score, SEV_ORDER.index(f.severity),
                       f.category, f.file, f.line)
    )
    return enriched


def build_scan_result(target, timestamp, stacks, tools_run, tools_skipped, all_findings):
    findings = enrich_findings(merge_findings(all_findings))
    return ScanResult(
        target=str(target),
        timestamp=timestamp,
        stacks=stacks,
        tools_run=tools_run,
        tools_skipped=tools_skipped,
        findings=findings,
    )
