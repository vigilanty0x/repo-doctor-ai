"""Deterministic renderers for machine and human review."""

from __future__ import annotations

from html import escape
import json
from typing import Any
from urllib.parse import quote

from . import __version__
from .models import Finding, Report
from .rules import RULE_HELP
from .sanitization import safe_output_text


def render_text(report: Report) -> str:
    payload = report.as_dict()
    lines = [
        f"Repo Doctor: {payload['state']} / {payload['result']} ({payload['reason_code']})",
        (
            f"Score {payload['score']['value']}/100 ({payload['score']['maturity']}); "
            f"scanned {payload['metrics'].get('files_scanned', 0)} text files; "
            f"{payload['summary']['total']} active and {payload['summary']['suppressed']} suppressed findings."
        ),
    ]
    for finding in report.findings:
        where = _where(finding)
        lines.append(f"[{finding.severity.upper()}] {finding.code}{where} — {finding.message}")
        lines.append(f"  Evidence: {finding.evidence or 'none'}")
        lines.append(f"  Fix: {finding.remediation}")
    return "\n".join(lines) + "\n"


def render_sarif(report: Report) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    levels = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in report.findings:
        rules.setdefault(
            finding.code,
            {
                "id": finding.code,
                "shortDescription": {"text": RULE_HELP.get(finding.code, finding.message)},
                "help": {"text": finding.remediation},
                "properties": {"category": finding.category},
            },
        )
        result: dict[str, Any] = {
            "ruleId": finding.code,
            "level": levels[finding.severity],
            "message": {"text": finding.message},
            "fingerprints": {"repoDoctor/v2": finding.fingerprint},
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {"classification": finding.classification, "evidence": finding.evidence},
        }
        if finding.path:
            physical: dict[str, Any] = {
                "artifactLocation": {"uri": quote(finding.path, safe="/-._~")}
            }
            if finding.line:
                physical["region"] = {"startLine": finding.line}
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Repo Doctor AI",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/vigilanty0x/repo-doctor-ai",
                        "rules": [rules[code] for code in sorted(rules)],
                    }
                },
                "automationDetails": {"description": {"text": "Offline deterministic repository audit"}},
                "properties": report.as_dict()["score"],
                "results": results,
            }
        ],
    }


def render_markdown(report: Report) -> str:
    payload = report.as_dict()
    lines = [
        "# Repo Doctor report",
        "",
        f"- Audit: **{payload['state']} / {payload['result']}** (`{payload['reason_code']}`)",
        f"- Score: **{payload['score']['value']}/100** — {payload['score']['maturity']}",
        f"- Inventory: {payload['metrics'].get('files_scanned', 0)} text files, {payload['metrics'].get('bytes_read', 0)} bytes",
        f"- Findings: {payload['summary']['total']} active, {payload['summary']['suppressed']} suppressed",
        "",
        "## Active findings",
        "",
    ]
    if not report.findings:
        lines.append("No active findings.")
    else:
        lines.extend(("| Severity | Code | Location | Evidence | Remediation |", "|---|---|---|---|---|"))
        for finding in report.findings:
            location = (finding.path or "—") + (f":{finding.line}" if finding.line else "")
            values = [finding.severity, finding.code, location, finding.evidence or "—", finding.remediation]
            lines.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")
    if report.suppressed_findings:
        lines.extend(("", "## Suppressed by baseline", ""))
        for item in report.suppressed_findings:
            expiry = item.expires or "no expiry"
            lines.append(
                f"- `{item.finding.code}` `{item.finding.fingerprint}` — "
                f"{safe_output_text(item.reason)} ({expiry})"
            )
    return "\n".join(lines) + "\n"


def render_html(report: Report) -> str:
    payload = report.as_dict()
    rows = []
    for finding in report.findings:
        location = (finding.path or "—") + (f":{finding.line}" if finding.line else "")
        rows.append(
            "<tr>"
            f"<td><span class=\"sev {escape(finding.severity)}\">{escape(finding.severity)}</span></td>"
            f"<td><code>{escape(finding.code)}</code></td>"
            f"<td><code>{escape(location)}</code></td>"
            f"<td>{escape(finding.evidence or '—')}</td>"
            f"<td>{escape(finding.remediation)}</td>"
            "</tr>"
        )
    body = "".join(rows) or '<tr><td colspan="5">No active findings.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Repo Doctor report</title><style>
:root{{--bg:#0b1020;--panel:#141b2d;--text:#edf2ff;--muted:#aebbd5;--line:#33415f;--accent:#7dd3fc}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:1200px;margin:auto;padding:2rem}}.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1rem}}.value{{font-size:1.7rem;font-weight:750}}
table{{width:100%;border-collapse:collapse;margin-top:1.5rem;background:var(--panel)}}th,td{{padding:.75rem;border:1px solid var(--line);text-align:left;vertical-align:top}}
th{{color:var(--accent)}}code{{overflow-wrap:anywhere}}.sev{{font-weight:700;text-transform:uppercase}}.critical,.high{{color:#fda4af}}.medium{{color:#fde68a}}.low{{color:#bae6fd}}
</style></head><body><main><h1>Repo Doctor report</h1><div class="summary">
<div class="card"><div>Audit</div><div class="value">{escape(payload['state'])} / {escape(payload['result'])}</div></div>
<div class="card"><div>Score</div><div class="value">{payload['score']['value']}/100</div><div>{escape(payload['score']['maturity'])}</div></div>
<div class="card"><div>Inventory</div><div class="value">{payload['metrics'].get('files_scanned', 0)}</div><div>text files</div></div>
<div class="card"><div>Findings</div><div class="value">{payload['summary']['total']}</div><div>{payload['summary']['suppressed']} suppressed</div></div>
</div><table><thead><tr><th>Severity</th><th>Code</th><th>Location</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>{body}</tbody></table>
</main></body></html>\n"""


def serialize(report: Report, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "markdown":
        return render_markdown(report)
    if output_format == "html":
        return render_html(report)
    payload = report.as_dict() if output_format == "json" else render_sarif(report)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _where(finding: Finding) -> str:
    if not finding.path:
        return ""
    return " " + finding.path + (f":{finding.line}" if finding.line else "")


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
