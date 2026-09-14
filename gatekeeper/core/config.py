"""Policy-as-code: per-repository configuration for Gatekeeper.

Gatekeeper reads `gatekeeper.yml` (or `gatekeeper.yaml`) from the target
repository root - or any path passed explicitly - and merges it over the
defaults. The file lets teams version their security policy next to the code:

    # gatekeeper.yml
    fail_on: high                  # exit 1 when findings >= this severity
    min_risk_score: 80             # ...or when any finding scores >= this
    tools: [semgrep, trivy, gitleaks]
    ignore_paths:
      - tests/fixtures/
      - vendor/
    ignore:
      - title: "Hardcoded JWT secret"      # exact title match
        reason: "test fixture, not a real credential"
      - fingerprint: "semgrep:secrets:config/settings.py:..."
    notifications:
      slack: https://hooks.slack.com/services/...
      webhook: https://example.com/hook

YAML parsing uses a small built-in subset parser (indentation-based maps,
`- item` lists, scalars) so Gatekeeper stays dependency-free. It covers the
shapes above; exotic YAML (anchors, multi-line strings) is not supported.
"""
import json
import re
from pathlib import Path

CONFIG_NAMES = ("gatekeeper.yml", "gatekeeper.yaml")

DEFAULTS = {
    "tools": None,             # None = auto-detect by stack
    "fail_on": "high",         # severity that flips the exit code to 1
    "min_risk_score": None,    # alternative gate: any finding >= N fails
    "ignore_paths": [],
    "ignore": [],
    "notifications": {},
    "validate_secrets": False,
}

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ------------------------------------------------------------- YAML subset --

def _scalar(token: str):
    token = token.strip()
    if token in ("", "~", "null"):
        return None
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        return [_scalar(part) for part in inner.split(",")] if inner else []
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if re.fullmatch(r"-?\d+\.\d+", token):
        return float(token)
    if (token.startswith('"') and token.endswith('"')) or \
       (token.startswith("'") and token.endswith("'")):
        return token[1:-1]
    return token


def _strip_comment(line: str) -> str:
    """Remove a trailing comment, respecting quoted strings."""
    out, quote = [], ""
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def parse_simple_yaml(text: str):
    """Parse the supported YAML subset into Python objects."""
    lines = []
    for raw in text.splitlines():
        raw = _strip_comment(raw)
        if raw.strip():
            lines.append(raw)
    value, _ = _parse_block(lines, 0, 0)
    return value if value is not None else {}


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines: list, pos: int, indent: int):
    """Parse lines[pos:] at the given indentation. Returns (value, next_pos)."""
    if pos >= len(lines):
        return None, pos
    first = lines[pos]
    return _parse_list(lines, pos, _indent_of(first)) \
        if first.lstrip().startswith("- ") else _parse_map(lines, pos, _indent_of(first))


def _parse_map(lines: list, pos: int, indent: int):
    result = {}
    while pos < len(lines):
        line = lines[pos]
        cur = _indent_of(line)
        if cur < indent or cur > indent or line.lstrip().startswith("- "):
            break
        stripped = line.strip()
        if ":" not in stripped:
            break
        key, _, rest = stripped.partition(":")
        key = key.strip().strip("\"'")
        rest = rest.strip()
        if rest:
            result[key] = _scalar(rest)
            pos += 1
            continue
        pos += 1
        if pos < len(lines) and _indent_of(lines[pos]) > indent:
            result[key], pos = _parse_block(lines, pos, _indent_of(lines[pos]))
        elif pos < len(lines) and _indent_of(lines[pos]) == indent \
                and lines[pos].lstrip().startswith("- ") and key not in result:
            # list items at the same indent as the parent key
            result[key], pos = _parse_list(lines, pos, indent)
        else:
            result[key] = None
    return result, pos


def _parse_list(lines: list, pos: int, indent: int):
    result = []
    while pos < len(lines):
        line = lines[pos]
        cur = _indent_of(line)
        if cur < indent or not line.lstrip().startswith("- "):
            break
        item = line.strip()[2:].strip()
        if ":" in item and not (item.startswith('"') or item.startswith("'")):
            # inline "key: value" starting a nested map inside a list
            key, _, rest = item.partition(":")
            sub = {key.strip(): _scalar(rest)}
            pos += 1
            while pos < len(lines):
                nxt = lines[pos]
                if _indent_of(nxt) > indent and not nxt.lstrip().startswith("- "):
                    k, _, r = nxt.strip().partition(":")
                    sub[k.strip()] = _scalar(r.strip())
                    pos += 1
                else:
                    break
            result.append(sub)
        else:
            result.append(_scalar(item))
            pos += 1
    return result, pos


# ------------------------------------------------------------------ public --

def load_config(target=None, path=None) -> dict:
    """Load gatekeeper.yml from the target repo (or an explicit path) and
    merge it over the defaults. Unknown keys are ignored. Never raises."""
    cfg = dict(DEFAULTS)
    candidates = []
    if path:
        candidates.append(Path(path))
    elif target:
        base = Path(target)
        candidates += [base / name for name in CONFIG_NAMES]
    for candidate in candidates:
        if candidate.is_file():
            try:
                data = parse_simple_yaml(candidate.read_text())
            except OSError:
                return cfg
            if isinstance(data, dict):
                cfg.update({k: v for k, v in data.items() if k in DEFAULTS})
            break
    return cfg


def severity_meets(severity: str, threshold: str) -> bool:
    """True when `severity` is at or above the threshold."""
    return _SEV_ORDER.get((severity or "").lower(), 0) >= \
        _SEV_ORDER.get((threshold or "").lower(), 3)


def failing_findings(findings: list, config: dict) -> list:
    """Findings that trip the policy gate (severity threshold and/or risk)."""
    threshold = config.get("fail_on") or "high"
    if str(threshold).lower() in ("none", "off", "never"):
        return []
    min_risk = config.get("min_risk_score")
    out = []
    for f in findings:
        sev = f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "")
        risk = f.get("risk_score") if isinstance(f, dict) else getattr(f, "risk_score", 0)
        blocked = severity_meets(sev, threshold)
        if min_risk is not None and isinstance(risk, int) and risk >= int(min_risk):
            blocked = True
        if blocked:
            out.append(f)
    return out


def finding_ignored(finding: dict, config: dict) -> bool:
    """True when the finding matches an `ignore` entry (title or fingerprint)
    or lives under one of the `ignore_paths` prefixes."""
    title = (finding.get("title") or "").strip().lower()
    fp = finding.get("fingerprint") or ""
    file = (finding.get("file") or "").replace("\\", "/").lstrip("./")
    for entry in config.get("ignore") or []:
        if isinstance(entry, str):
            if entry.lower() == title:
                return True
            continue
        if not isinstance(entry, dict):
            continue
        match = str(entry.get("title", "")).strip().lower()
        if match and match == title:
            return True
        match_fp = str(entry.get("fingerprint", "")).strip()
        if match_fp and fp.startswith(match_fp):
            return True
    for prefix in config.get("ignore_paths") or []:
        prefix = str(prefix).replace("\\", "/").strip("/")
        if prefix and (file == prefix or file.startswith(prefix + "/")):
            return True
    return False


def filter_findings(findings: list, config: dict) -> list:
    """Drop findings excluded by the repository policy."""
    return [f for f in findings if not finding_ignored(f, config)]


def to_jsonable(config: dict) -> dict:
    return json.loads(json.dumps(config, default=str))
