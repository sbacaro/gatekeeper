"""Risk scoring, CWE and OWASP mapping - the Aikido-parity intelligence layer.

risk_score (0-100) is computed from:
  - severity (dominant factor)
  - CVSS score when the scanner provides one
  - exploitability signals (known exploits, reachable code, secrets in history)
  - category weight (secrets in history are instantly weaponizable, etc.)
"""
import re

SEV_BASE = {"CRITICAL": 78, "HIGH": 60, "MEDIUM": 38, "LOW": 18, "INFO": 6}
CAT_BOOST = {"secrets": 12, "sast": 6, "dast": 6, "sca": 3, "iac": 2}

_EXPLOIT_WORDS = (
    "injection", "rce", "deserializ", "command", "sql", "xxe", "ssrf",
    "path traversal", "log4shell", "spring4shell", "auth bypass",
)

# CWE -> OWASP Top 10 2021 mapping for the classes our scanners emit.
_CWE_OWASP = {
    "CWE-20": "A03:2021 - Injection",
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-22 ": "A01:2021 - Broken Access Control",
    "CWE-78": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-209": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-215": "A05:2021 - Security Misconfiguration",
    "CWE-259": "A07:2021 - Identification and Authentication Failures",
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-295": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-328": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-384": "A07:2021 - Identification and Authentication Failures",
    "CWE-400": "A05:2021 - Security Misconfiguration",
    "CWE-400 ": "A05:2021 - Security Misconfiguration",
    "CWE-471": "A04:2021 - Insecure Design",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-521": "A07:2021 - Identification and Authentication Failures",
    "CWE-522": "A07:2021 - Identification and Authentication Failures",
    "CWE-532": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-598": "A07:2021 - Identification and Authentication Failures",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-732": "A01:2021 - Broken Access Control",
    "CWE-770": "A04:2021 - Insecure Design",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-829": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-916": "A02:2021 - Cryptographic Failures",
    "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
    "CWE-1104": "A06:2021 - Vulnerable and Outdated Components",
}

_CWE_RE = re.compile(r"CWE-\d+")


def cwe_of(text: str) -> str:
    m = _CWE_RE.search(text or "")
    return m.group(0) if m else ""


def owasp_of(cwe: str) -> str:
    return _CWE_OWASP.get(cwe, "")


def _cvss_to_sev_bonus(cvss: float | None) -> int:
    if cvss is None:
        return 0
    # Align with CVSS qualitative bands: 9.0-10 critical, 7.0-8.9 high...
    return int((cvss / 10.0) * 22)


def exploit_bonus(f) -> int:
    text = " ".join(str(f.get(k, "")) for k in ("title", "description", "cwe")).lower()
    bonus = 0
    if any(w in text for w in _EXPLOIT_WORDS):
        bonus += 8
    if f.get("category") == "secrets":
        # committed secrets are directly usable by an attacker
        bonus += 8
    return bonus


def compute_risk(f: dict) -> int:
    """0-100 risk score. Severity dominates, CVSS refines, exploitability
    signals and category weight nudge it up."""
    sev = (f.get("severity") or "INFO").upper()
    score = SEV_BASE.get(sev, 6)
    score += _cvss_to_sev_bonus(f.get("cvss"))
    score += exploit_bonus(f)
    score += {"sast": 0, "sca": 0, "secrets": 0, "iac": 0, "dast": 0}.get(
        f.get("category"), 0)
    score = min(100, score)
    # Secrets live in a tier of their own regardless of nominal severity.
    if f.get("category") == "secrets" and score < 85:
        score = max(score, 82)
    return score
