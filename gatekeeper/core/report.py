"""Generate REPORT.md and REPORT.html from a ScanResult."""
import html
from pathlib import Path

from gatekeeper.core.models import SEVERITY_ORDER
from gatekeeper.core.sarif import write_sarif

SEV_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "⚪ INFO",
}

# Severity -> CSS class in the HTML report. Colors live exclusively in the
# CSS custom properties (--sev-*) so the report stays themeable.
SEV_CLASS = {
    "CRITICAL": "sev-critical",
    "HIGH": "sev-high",
    "MEDIUM": "sev-medium",
    "LOW": "sev-low",
    "INFO": "sev-info",
}


def _counts(findings):
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f["severity"] if isinstance(f, dict) else f.severity
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _location(f):
    file = f["file"] if isinstance(f, dict) else f.file
    line = f["line"] if isinstance(f, dict) else f.line
    if not file:
        return "n/a"
    return f"{file}:{line}" if line else file


def _threat_meta(f) -> str:
    parts = []
    if f.get("kev"):
        parts.append("🚨 KEV (actively exploited)")
    if f.get("ransomware"):
        parts.append("ransomware campaign")
    if f.get("epss") is not None:
        parts.append(f"EPSS {f['epss']*100:.1f}%")
    return "; ".join(parts)


def report_markdown(result: dict) -> str:
    findings = result["findings"]
    counts = _counts(findings)
    lines = [
        f"# Security Report - {result['target']}",
        "",
        f"Generated: {result['timestamp']}",
        "",
        f"**Stacks detected:** "
        f"{', '.join(k for k, v in result['stacks'].items() if v and k != 'code') or 'none'}",
        f"**Tools run:** {', '.join(result['tools_run']) or 'none'}",
        f"**Tools skipped:** {', '.join(result['tools_skipped']) or 'none'}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {SEV_BADGE[sev]} | {counts.get(sev, 0)} |")
    lines += [
        f"| **Total** | **{len(findings)}** |",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No findings. 🎉")
    for i, f in enumerate(findings, 1):
        meta = []
        if f.get("cvss") is not None:
            meta.append(f"CVSS {f['cvss']}")
        if f.get("cwe"):
            meta.append(f["cwe"] + (f" ({f['owasp']})" if f.get("owasp") else ""))
        if f.get("package"):
            meta.append(f"pkg: {f['package']}")
        if f.get("introduced_via"):
            meta.append("via: " + " -> ".join(f["introduced_via"]))
        if f.get("risk_score"):
            meta.append(f"risk {f['risk_score']}/100")
        lines += [
            f"### {i}. [{f['severity']}] {f['title']}",
            "",
            f"- **Tool:** {f['tool']} ({f['category']})",
            f"- **Location:** `{_location(f)}`",
            f"- **Description:** {f['description']}",
            f"- **Remediation:** {f['remediation_hint']}",
        ]
        threat = _threat_meta(f)
        if threat:
            lines.append(f"- **Threat intel:** {threat}")
        if meta:
            lines.append(f"- **Metadata:** {('; '.join(meta))}")
        if f.get("code_snippet"):
            lines += ["", "```", f["code_snippet"], "```"]
        lines.append("")
    return "\n".join(lines)


def report_html(result: dict) -> str:
    findings = result["findings"]
    counts = _counts(findings)
    rows = []
    for i, f in enumerate(findings, 1):
        sev_cls = SEV_CLASS.get(f["severity"], "sev-info")
        threat = _threat_meta(f)
        threat_html = (f"<br><small>{html.escape(threat)}</small>" if threat else "")
        rows.append(f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge {sev_cls}">
              {html.escape(f['severity'])}</span>{threat_html}</td>
          <td>{html.escape(f['title'])}</td>
          <td>{html.escape(f['tool'])}<br><small>{html.escape(f['category'])}</small></td>
          <td><code>{html.escape(_location(f))}</code></td>
          <td>{html.escape(f['description'])}</td>
          <td>{html.escape(f['remediation_hint'])}</td>
        </tr>""")

    summary_cells = "".join(
        f"<td class='{SEV_CLASS[s]}'>{counts.get(s, 0)}</td>"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Gatekeeper Report - {html.escape(result['target'])}</title>
<style>
  :root {{
    --bg: #ffffff; --text: #111827; --muted: #4b5563;
    --border: #d1d5db; --head-bg: #f3f4f6; --code-bg: #f3f4f6;
    --sev-critical: #7f1d1d; --sev-high: #9a3412; --sev-medium: #a16207;
    --sev-low: #1d4ed8; --sev-info: #4b5563; --badge-fg: #ffffff;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #12121f; --text: #e8e8f2; --muted: #9494a8;
      --border: #2c2c40; --head-bg: #1d1d30; --code-bg: #1d1d30;
      --sev-critical: #f87171; --sev-high: #fb923c; --sev-medium: #fbbf24;
      --sev-low: #60a5fa; --sev-info: #7c7c95;
      color-scheme: dark;
    }}
  }}
  body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem;
         background: var(--bg); color: var(--text); }}
  table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
  th, td {{ border: 1px solid var(--border); padding: 8px; text-align: left; vertical-align: top; }}
  th {{ background: var(--head-bg); }}
  .badge {{ padding: 2px 8px; border-radius: 4px;
           font-weight: 600; font-size: 12px; }}
  .summary td {{ font-size: 20px; font-weight: 700; text-align: center; }}
  code {{ background: var(--code-bg); padding: 1px 4px; border-radius: 3px; }}
  .sev-critical {{ background: var(--sev-critical); color: var(--badge-fg); }}
  .sev-high {{ background: var(--sev-high); color: var(--badge-fg); }}
  .sev-medium {{ background: var(--sev-medium); color: var(--badge-fg); }}
  .sev-low {{ background: var(--sev-low); color: var(--badge-fg); }}
  .sev-info {{ background: var(--sev-info); color: var(--badge-fg); }}
  td.sev-critical, td.sev-high, td.sev-medium, td.sev-low, td.sev-info
    {{ color: var(--sev-critical); background: none; }}
  td.sev-high {{ color: var(--sev-high); }}
  td.sev-medium {{ color: var(--sev-medium); }}
  td.sev-low {{ color: var(--sev-low); }}
  td.sev-info {{ color: var(--sev-info); }}
</style>
</head>
<body>
<h1>Gatekeeper Security Report</h1>
<p><strong>Target:</strong> {html.escape(result['target'])} &middot;
   <strong>Generated:</strong> {html.escape(result['timestamp'])}</p>
<p><strong>Stacks:</strong> {html.escape(', '.join(
    k for k, v in result['stacks'].items() if v and k != 'code') or 'none')} &middot;
   <strong>Tools run:</strong> {html.escape(', '.join(result['tools_run']) or 'none')}</p>
<h2>Summary ({len(findings)} findings)</h2>
<table class="summary"><tr>
  <th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th>
</tr><tr>{summary_cells}</tr></table>
<h2>Findings</h2>
<table>
<tr><th>#</th><th>Severity</th><th>Title</th><th>Tool</th><th>Location</th><th>Description</th><th>Remediation</th></tr>
{''.join(rows) if rows else '<tr><td colspan="7">No findings found.</td></tr>'}
</table>
</body>
</html>"""


def write_reports(result: dict, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "REPORT.md").write_text(report_markdown(result))
    (out_dir / "REPORT.html").write_text(report_html(result))
    write_sarif(result, out_dir)
