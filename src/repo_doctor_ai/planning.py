"""Deterministic, evidence-linked remediation planning."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .diffing import ReportDataError, validate_report
from .models import SEVERITY_ORDER


def build_plan(report: Any) -> dict[str, Any]:
    validate_report(report)
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ReportDataError("document must contain a findings array")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in report["findings"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("code"), str):
            raise ReportDataError("finding must contain a code")
        if finding.get("severity") not in SEVERITY_ORDER or not isinstance(finding.get("remediation"), str):
            raise ReportDataError("finding severity or remediation is invalid")
        groups[finding["code"]].append(finding)
    work: list[dict[str, Any]] = []
    for code, findings in groups.items():
        highest = max(findings, key=lambda item: SEVERITY_ORDER[item["severity"]])["severity"]
        priority = 5 - SEVERITY_ORDER[highest]
        locations = []
        for finding in findings:
            location = finding.get("location")
            if isinstance(location, dict) and isinstance(location.get("path"), str):
                locations.append(
                    {"path": location["path"], "line": location.get("line")}
                )
        fingerprints = sorted(
            finding["fingerprint"]
            for finding in findings
            if isinstance(finding.get("fingerprint"), str)
        )
        work.append(
            {
                "priority": priority,
                "window": _window(highest),
                "severity": highest,
                "code": code,
                "category": str(findings[0].get("category", "unknown")),
                "count": len(findings),
                "action": findings[0]["remediation"],
                "acceptance": f"A fresh scan contains no active {code} findings and relevant tests pass.",
                "effort": _effort(str(findings[0].get("category", "unknown")), len(findings)),
                "fingerprints": fingerprints,
                "locations": sorted(locations, key=lambda value: (value["path"], value["line"] or 0))[:25],
                "locations_omitted": max(0, len(locations) - 25),
            }
        )
    work.sort(key=lambda item: (item["priority"], item["category"], item["code"]))
    return {
        "schema": "repo-doctor-remediation-plan/1",
        "source": {
            "root": report.get("root"),
            "report_version": report.get("report_version"),
            "active_findings": len(report["findings"]),
        },
        "summary": {
            "work_items": len(work),
            "immediate": sum(item["window"] == "immediate" for item in work),
            "near_term": sum(item["window"] == "near-term" for item in work),
            "planned": sum(item["window"] == "planned" for item in work),
        },
        "work_items": work,
    }


def render_plan_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Repo Doctor remediation plan",
        "",
        f"Active findings: **{plan['source']['active_findings']}** across **{plan['summary']['work_items']}** work items.",
        "",
    ]
    if not plan["work_items"]:
        lines.append("No remediation work is currently required.")
        return "\n".join(lines) + "\n"
    for item in plan["work_items"]:
        lines.extend(
            (
                f"## P{item['priority']} — {item['code']}",
                "",
                f"- Severity/window: {item['severity']} / {item['window']}",
                f"- Scope: {item['count']} finding(s), effort {item['effort']}",
                f"- Action: {item['action']}",
                f"- Acceptance: {item['acceptance']}",
                "",
            )
        )
    return "\n".join(lines)


def _window(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "immediate"
    if severity == "medium":
        return "near-term"
    return "planned"


def _effort(category: str, count: int) -> str:
    base = {
        "secrets": 3,
        "ci": 2,
        "dependencies": 2,
        "debt": 3,
        "repository": 2,
        "structure": 1,
        "tests": 3,
        "ownership": 1,
        "documentation": 2,
        "release": 2,
    }.get(category, 2)
    value = min(5, base + (1 if count > 10 else 0))
    return {1: "xs", 2: "s", 3: "m", 4: "l", 5: "xl"}[value]
