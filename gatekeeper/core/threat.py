"""Threat intelligence enrichment: CISA KEV and FIRST EPSS.

Replaces keyword-based exploitability heuristics with authoritative public
feeds:
  - CISA KEV (Known Exploited Vulnerabilities): definitive signal that a CVE
    is being exploited in the wild. Updated daily.
  - EPSS (Exploit Prediction Scoring System): probability (0-1) that a CVE
    will be exploited in the next 30 days.

Both are downloaded as bulk files and cached locally (default: 24h TTL), so
scans work fully offline after the first refresh and never leak target info.
"""
import csv
import io
import json
import time
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyber.ku.edu/api/v2/epss-enriched.csv.gz"

CACHE_TTL = 24 * 3600
CACHE_DIR = Path.home() / ".cache" / "gatekeeper"
KEV_CACHE = CACHE_DIR / "kev.json"
EPSS_CACHE = CACHE_DIR / "epss.csv"

_FETCH_TIMEOUT = 60


def _cache_fresh(path: Path, ttl: int = CACHE_TTL) -> bool:
    try:
        return time.time() - path.stat().st_mtime < ttl
    except OSError:
        return False


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "gatekeeper/1.0"})
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
        return resp.read()


def _load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# ------------------------------------------------------------------- KEV ----

def _download_kev() -> dict:
    data = json.loads(_download(KEV_URL))
    mapping = {}
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cveID", "")
        if cve:
            mapping[cve] = {
                "date_added": entry.get("dateAdded", ""),
                "due_date": entry.get("dueDate", ""),
                "known_ransomware": entry.get("knownRansomwareCampaignUse", "") == "Known",
            }
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = KEV_CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps(mapping))
    tmp.replace(KEV_CACHE)
    return mapping


def load_kev(max_age: int = CACHE_TTL) -> dict:
    """CVE -> KEV metadata dict. Empty dict when offline and no cache."""
    if _cache_fresh(KEV_CACHE, max_age):
        cached = _load_json(KEV_CACHE)
        if isinstance(cached, dict):
            return cached
    try:
        return _download_kev()
    except Exception:
        cached = _load_json(KEV_CACHE)
        return cached if isinstance(cached, dict) else {}


# ------------------------------------------------------------------ EPSS ----

def _download_epss() -> dict:
    import gzip
    raw = gzip.decompress(_download(EPSS_URL))
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")))
    mapping = {}
    for row in reader:
        cve = row.get("cve") or row.get("cve_id") or ""
        score = row.get("epss") or row.get("score") or ""
        try:
            mapping[cve] = float(score)
        except (TypeError, ValueError):
            continue
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = EPSS_CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps(mapping))
    tmp.replace(EPSS_CACHE)
    return mapping


def load_epss(max_age: int = CACHE_TTL) -> dict:
    """CVE -> EPSS probability (0-1). Empty dict when offline and no cache."""
    if _cache_fresh(EPSS_CACHE, max_age):
        cached = _load_json(EPSS_CACHE)
        if isinstance(cached, dict):
            return cached
    try:
        return _download_epss()
    except Exception:
        cached = _load_json(EPSS_CACHE)
        return cached if isinstance(cached, dict) else {}


# ---------------------------------------------------------------- scoring ---

KEV_BONUS = 25            # actively exploited: dominates every other signal
RANSOMWARE_BONUS = 5      # KEV entry tied to a known ransomware campaign
EPSS_BONUS_MAX = 15       # linear in EPSS probability, capped

# EPSS percentiles where SCA findings get their severity re-banded.
EPSS_CRITICAL = 0.5       # top ~0.5% of the distribution
EPSS_HIGH = 0.1


def enrich_with_threat_intel(findings, kev: dict, epss: dict):
    """Attach kev/epss fields to finding dicts in place and return them.

    findings items are dicts (as produced by Finding.to_dict()).
    """
    for f in findings:
        cve = _cve_of(f)
        if not cve:
            continue
        if cve in kev:
            f["kev"] = True
            f["kev_date"] = kev[cve].get("date_added", "")
            f["ransomware"] = kev[cve].get("known_ransomware", False)
        score = epss.get(cve)
        if score is not None:
            f["epss"] = round(float(score), 5)
    return findings


def _cve_of(f) -> str:
    import re
    m = re.search(r"CVE-\d{4}-\d+", f.get("title", "") + " " + f.get("description", ""),
                  re.IGNORECASE)
    return m.group(0).upper() if m else ""


def threat_bonus(f: dict) -> int:
    """Risk bonus from real-world exploitation signals (0-45)."""
    bonus = 0
    if f.get("kev"):
        bonus += KEV_BONUS
        if f.get("ransomware"):
            bonus += RANSOMWARE_BONUS
    epss = f.get("epss")
    if isinstance(epss, (int, float)):
        bonus += int(min(1.0, epss) * EPSS_BONUS_MAX)
    return bonus
