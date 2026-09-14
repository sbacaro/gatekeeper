"""SARIF 2.1.0 export for GitHub Code Scanning and IDE integrations."""
import re
from pathlib import Path

_RULE_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
               "LOW": "note", "INFO": "note"}


def _g(f, key, default=""):
    """Dict-or-object accessor: findings may be dicts or Finding dataclasses."""
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def _rules(findings):
    """One rule entry per unique (tool, title) pair."""
    seen = {}
    rules = []
    for f in findings:
        tool = _g(f, "tool", "gatekeeper")
        title = _g(f, "title", "")
        key = (tool, title)
        if key in seen:
            continue
        seen[key] = True
        rule = {
            "id": _rule_id(f),
            "name": title[:120],
            "shortDescription": {"text": title[:300]},
            "fullDescription": {"text": (_g(f, "description") or "")[:1000]},
            "defaultConfiguration": {
                "level": _RULE_LEVEL.get(_g(f, "severity"), "note")},
            "properties": {
                "security-severity": _security_severity(f),
                "tags": [t for t in (
                    _g(f, "category"), _g(f, "cwe"), _g(f, "owasp"),
                ) if t],
            },
        }
        cwe = _g(f, "cwe")
        if cwe:
            rule["properties"]["tags"].append(
                f"external/cwe/{cwe.replace('CWE-', 'cwe-')}")
        help_text = _g(f, "remediation_hint") or ""
        if help_text:
            rule["help"] = {"text": help_text[:1000]}
        rules.append(rule)
    return rules


def _security_severity(f) -> str:
    """GitHub security-severity (CVSS-like 0.0-10.0) derived from risk score."""
    risk = _g(f, "risk_score") or 0
    return f"{min(10.0, risk / 10.0):.1f}"


def _rule_id(f) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", _g(f, "title", "finding"))
    slug = slug.strip("-")[:60] or "finding"
    return f"{_g(f, 'tool', 'gatekeeper')}/{slug.lower()}"


def _result(f, target: str):
    uri = _g(f, "file", "") or ""
    uri = uri.replace(str(target), "").lstrip("/\\")
    line = max(1, int(_g(f, "line") or 1))
    message = _g(f, "description") or _g(f, "title", "")
    result = {
        "ruleId": _rule_id(f),
        "level": _RULE_LEVEL.get(_g(f, "severity"), "note"),
        "message": {"text": message[:2000]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": line, "startColumn": 1,
                    "endLine": line, "endColumn": 2,
                },
            },
        }],
        "partialFingerprints": {
            "gatekeeperFingerprint/v1": _g(f, "fingerprint", "")},
        "properties": {
            "severity": _g(f, "severity"),
            "risk-score": _g(f, "risk_score", 0),
        },
    }
    if _g(f, "kev"):
        result["properties"]["known-exploited"] = True
    if _g(f, "epss") is not None:
        result["properties"]["epss"] = _g(f, "epss")
    return result


def sarif_report(result: dict) -> dict:
    findings = result.get("findings", [])
    target = result.get("target", "")
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                   "Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Gatekeeper",
                "informationUri": "https://github.com/sbacaro/gatekeeper",
                "semanticVersion": "1.0.0",
                "rules": _rules(findings),
            }},
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": Path(target).as_uri() + "/"},
            },
            "results": [_result(f, target) for f in findings],
        }],
    }


def write_sarif(result: dict, out_dir: Path):
    import json
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "gatekeeper.sarif").write_text(
        json.dumps(sarif_report(result), indent=2))
