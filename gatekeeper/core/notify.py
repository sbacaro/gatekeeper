"""Scan notifications: Slack and generic webhooks, zero dependencies.

Configured in gatekeeper.yml:

    notifications:
      slack: https://hooks.slack.com/services/T000/B000/xxxx
      webhook: https://ci.example.com/hook?token=...
      # optional
      min_severity: high      # only notify for findings >= this severity
      on_pass: false          # also notify when the gate passes

Delivery is best-effort: failures are collected and reported but never raise,
so a broken webhook cannot fail a scan or a CI gate.
"""
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _post(url: str, payload: dict, timeout: int = 10) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 300, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except (urllib.error.URLError, OSError) as exc:
        return False, str(exc)[:160]


def _summarize(findings: list) -> dict:
    counts = {}
    for f in findings:
        counts[f.get("severity", "?")] = counts.get(f.get("severity", "?"), 0) + 1
    return counts


def slack_blocks(target: str, verdict: str, findings: list, config: dict) -> dict:
    """Build a Slack incoming-webhook payload with the top findings."""
    emoji = ":white_check_mark:" if verdict == "PASSED" else ":rotating_light:"
    color = "good" if verdict == "PASSED" else "danger"
    head = f"{emoji} *Gatekeeper {verdict}* - `{target}`"
    lines = [f"_{len(findings)} blocking finding(s)_ - "
             f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"]
    for f in findings[:10]:
        lines.append(f"`[{f.get('severity')}]` *{f.get('title', '')[:80]}*"
                     f"{(' - ' + f['file']) if f.get('file') else ''}")
    if len(findings) > 10:
        lines.append(f"_...and {len(findings) - 10} more_")
    return {
        "text": head,
        "attachments": [{
            "color": color,
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": head + "\n" + "\n".join(lines)},
            }],
        }],
    }


def notify_scan_result(target: str, verdict: str, findings: list, config: dict,
                       progress=None) -> dict:
    """Deliver the scan outcome to every channel in config['notifications'].

    `verdict` is "PASSED" or "FAILED". Returns a per-channel delivery report;
    never raises.
    """
    notif = config.get("notifications") or {}
    if not isinstance(notif, dict):
        return {}

    min_sev = (notif.get("min_severity") or "").lower()
    if min_sev:
        findings = [f for f in findings
                    if SEV_RANK.get(f.get("severity", ""), 0)
                    >= SEV_RANK.get(min_sev.upper(), 4)]
    if verdict == "PASSED" and not notif.get("on_pass"):
        return {}
    if not findings and verdict != "PASSED":
        findings = [{"severity": "INFO",
                     "title": "Gatekeeper scan FAILED with no matching findings"}]

    report = {}
    message = {
        "target": str(target),
        "verdict": verdict,
        "counts": _summarize(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": [{
            "severity": f.get("severity"), "title": f.get("title"),
            "file": f.get("file"), "line": f.get("line"),
            "risk_score": f.get("risk_score"),
        } for f in findings[:25]],
    }

    for key, url in (("slack", notif.get("slack")),
                     ("webhook", notif.get("webhook"))):
        if not url:
            continue
        payload = slack_blocks(str(target), verdict, findings, config) \
            if key == "slack" else message
        try:
            ok, detail = _post(str(url), payload)
        except Exception as exc:  # a broken channel must never fail a scan
            ok, detail = False, str(exc)[:160]
        report[key] = {"ok": ok, "detail": detail}
        if progress:
            progress("notify", channel=key, ok=ok, detail=detail)
    return report
