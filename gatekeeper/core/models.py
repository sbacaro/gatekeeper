"""Core data structures shared across Gatekeeper modules."""
from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

CATEGORIES = ("sast", "sca", "secrets", "iac", "dast")


@dataclass
class Finding:
    id: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    tool: str              # semgrep | trivy | gitleaks | osv-scanner | zap | mobsf
    category: str          # sast | sca | secrets | iac | dast
    file: str              # relative path, "" when N/A
    line: int              # 0 when N/A
    title: str
    description: str
    remediation_hint: str
    fingerprint: str = ""
    # --- enriched metadata (Aikido-parity) ---
    cvss: float | None = None          # CVSS v3 base score when available
    cwe: str = ""                      # e.g. "CWE-79"
    owasp: str = ""                    # e.g. "A03:2021 - Injection"
    introduced_via: list = field(default_factory=list)  # dependency chain
    package: str = ""                  # pkg@version for SCA findings
    risk_score: int = 0                # 0-100 computed risk ranking
    code_snippet: str = ""             # source excerpt around the finding

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    timestamp: str
    stacks: dict
    tools_run: list = field(default_factory=list)
    tools_skipped: list = field(default_factory=list)
    findings: list = field(default_factory=list)   # list[Finding]

    def to_dict(self):
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "stacks": self.stacks,
            "tools_run": self.tools_run,
            "tools_skipped": self.tools_skipped,
            "findings": [f.to_dict() for f in self.findings],
        }
