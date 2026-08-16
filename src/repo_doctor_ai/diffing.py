"""Stable report comparison and regression classification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from datetime import date
from typing import Any

from .io_utils import BoundedReadError, read_bounded_text
from .models import Finding, SEVERITY_ORDER
from .models import SEVERITY_PENALTY
from .sanitization import is_safe_output_text

MAX_REPORT_BYTES = 16 * 1024 * 1024
REPORT_FIELDS = {
    "report_version", "root", "state", "status", "result", "reason_code",
    "summary", "score", "metrics", "errors", "findings", "suppressed_findings",
}
FINDING_FIELDS = {
    "fingerprint", "code", "category", "severity", "classification", "message",
    "remediation", "location", "evidence",
}


class ReportDataError(ValueError):
    """A stored report is malformed or outside the bounded contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportDataError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ReportDataError(f"non-finite JSON number is not allowed: {value}")


def load_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    try:
        text = read_bounded_text(report_path, MAX_REPORT_BYTES, label="report")
        raw = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except ReportDataError:
        raise
    except (BoundedReadError, json.JSONDecodeError) as exc:
        raise ReportDataError(f"invalid report: {exc}") from exc
    validate_report(raw)
    return raw


def diff_reports(base: Any, current: Any) -> dict[str, Any]:
    validate_report(base)
    validate_report(current)
    before = {finding["fingerprint"]: finding for finding in _findings(base)}
    after = {finding["fingerprint"]: finding for finding in _findings(current)}
    new_ids = sorted(set(after) - set(before))
    resolved_ids = sorted(set(before) - set(after))
    shared = sorted(set(before).intersection(after))
    escalated_ids = [
        fingerprint
        for fingerprint in shared
        if SEVERITY_ORDER[after[fingerprint]["severity"]] > SEVERITY_ORDER[before[fingerprint]["severity"]]
    ]
    new = [after[fingerprint] for fingerprint in new_ids]
    resolved = [before[fingerprint] for fingerprint in resolved_ids]
    escalated = [
        {
            "fingerprint": fingerprint,
            "code": after[fingerprint]["code"],
            "from": before[fingerprint]["severity"],
            "to": after[fingerprint]["severity"],
        }
        for fingerprint in escalated_ids
    ]
    regression = bool(new or escalated)
    return {
        "schema": "repo-doctor-diff/1",
        "base_sha256": _digest(base),
        "current_sha256": _digest(current),
        "regression": regression,
        "summary": {
            "new": len(new),
            "resolved": len(resolved),
            "unchanged": len(shared) - len(escalated),
            "severity_escalated": len(escalated),
        },
        "new": new,
        "resolved": resolved,
        "severity_escalated": escalated,
    }


def render_diff_markdown(diff: dict[str, Any]) -> str:
    summary = diff["summary"]
    lines = [
        "# Repo Doctor regression diff",
        "",
        f"Regression: **{'yes' if diff['regression'] else 'no'}**",
        "",
        f"- New: {summary['new']}",
        f"- Resolved: {summary['resolved']}",
        f"- Unchanged: {summary['unchanged']}",
        f"- Severity escalated: {summary['severity_escalated']}",
        "",
        "## New findings",
        "",
    ]
    if not diff["new"]:
        lines.append("None.")
    for finding in diff["new"]:
        location = finding.get("location") or {}
        where = location.get("path") or "repository"
        if location.get("line"):
            where += f":{location['line']}"
        lines.append(f"- **{finding['severity']}** `{finding['code']}` at `{where}`")
    lines.extend(("", "## Resolved findings", ""))
    if not diff["resolved"]:
        lines.append("None.")
    for finding in diff["resolved"]:
        lines.append(f"- `{finding['code']}` `{finding['fingerprint']}`")
    return "\n".join(lines) + "\n"


def _findings(report: Any) -> list[dict[str, Any]]:
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ReportDataError("document must contain a findings array")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in report["findings"]:
        _validate_finding(finding)
        fingerprint = finding.get("fingerprint")
        severity = finding.get("severity")
        if fingerprint in seen:
            raise ReportDataError("report contains duplicate finding fingerprints")
        seen.add(fingerprint)
        results.append(finding)
    return results


def _validate_finding(finding: Any, *, suppressed: bool = False) -> None:
    expected = FINDING_FIELDS | ({"suppression"} if suppressed else set())
    if not isinstance(finding, dict) or set(finding) != expected:
        raise ReportDataError("finding has invalid or unknown fields")
    fingerprint = finding["fingerprint"]
    code = finding["code"]
    category = finding["category"]
    severity = finding["severity"]
    classification = finding["classification"]
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{20}", fingerprint):
        raise ReportDataError("finding fingerprint is invalid")
    if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code):
        raise ReportDataError("finding code is invalid")
    if not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", category):
        raise ReportDataError("finding category is invalid")
    if severity not in SEVERITY_ORDER or classification not in {"proof", "inference", "blockage"}:
        raise ReportDataError("finding severity or classification is invalid")
    for key, maximum in (("message", 2_000), ("remediation", 2_000)):
        value = finding[key]
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.encode("utf-8")) > maximum
            or not is_safe_output_text(value)
        ):
            raise ReportDataError(f"finding {key} is invalid")
    evidence = finding["evidence"]
    if evidence is not None and (
        not isinstance(evidence, str)
        or len(evidence.encode("utf-8")) > 4_096
        or not is_safe_output_text(evidence)
    ):
        raise ReportDataError("finding evidence is invalid")
    location = finding["location"]
    path: str | None = None
    line: int | None = None
    if location is not None:
        if not isinstance(location, dict) or set(location) != {"path", "line"}:
            raise ReportDataError("finding location is invalid")
        path, line = location["path"], location["line"]
        if (
            not isinstance(path, str)
            or not path
            or len(path.encode("utf-8")) > 1_024
            or not is_safe_output_text(path)
        ):
            raise ReportDataError("finding path is invalid")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            raise ReportDataError("finding line is invalid")
    expected_fingerprint = Finding(
        code, category, severity, classification, finding["message"], finding["remediation"], path, line, evidence
    ).fingerprint
    if fingerprint != expected_fingerprint:
        raise ReportDataError("finding fingerprint does not match its identity")
    if suppressed:
        suppression = finding["suppression"]
        if not isinstance(suppression, dict) or set(suppression) != {"reason", "expires"}:
            raise ReportDataError("suppression is invalid")
        reason, expires = suppression["reason"], suppression["expires"]
        if (
            not isinstance(reason, str)
            or not 8 <= len(reason.strip()) <= 500
            or not is_safe_output_text(reason)
        ):
            raise ReportDataError("suppression reason is invalid")
        if expires is not None:
            if not isinstance(expires, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
                raise ReportDataError("suppression expiry is invalid")
            try:
                date.fromisoformat(expires)
            except ValueError as exc:
                raise ReportDataError("suppression expiry is invalid") from exc


def validate_report(report: Any) -> None:
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        raise ReportDataError("report has invalid or unknown fields")
    if report["report_version"] != "2.0":
        raise ReportDataError("unsupported report_version")
    for key, values in (
        ("state", {"DONE", "DEGRADED", "WAITING", "REJECTED"}),
        ("status", {"verified", "blocked"}),
        ("result", {"PASS", "WARN", "FAIL"}),
    ):
        if report[key] not in values:
            raise ReportDataError(f"report {key} is invalid")
    if (
        not isinstance(report["root"], str)
        or not report["root"]
        or len(report["root"].encode("utf-8")) > 1_024
        or not is_safe_output_text(report["root"])
    ):
        raise ReportDataError("report root is invalid")
    if not isinstance(report["reason_code"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", report["reason_code"]):
        raise ReportDataError("report reason_code is invalid")
    if not isinstance(report["errors"], list) or any(
        not isinstance(item, str)
        or len(item.encode("utf-8")) > 2_000
        or not is_safe_output_text(item)
        for item in report["errors"]
    ):
        raise ReportDataError("report errors are invalid")
    if not isinstance(report["metrics"], dict) or any(
        not isinstance(key, str)
        or not is_safe_output_text(key)
        or isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        for key, value in report["metrics"].items()
    ):
        raise ReportDataError("report metrics are invalid")
    summary = report["summary"]
    if not isinstance(summary, dict) or set(summary) != {"total", "suppressed", "by_severity"}:
        raise ReportDataError("report summary is invalid")
    if not isinstance(summary["by_severity"], dict) or set(summary["by_severity"]) != set(SEVERITY_ORDER):
        raise ReportDataError("report severity summary is invalid")
    counts = [summary["total"], summary["suppressed"], *summary["by_severity"].values()]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
        raise ReportDataError("report summary counts are invalid")
    score = report["score"]
    if (
        not isinstance(score, dict)
        or set(score) != {"value", "raw_value", "maturity", "scale"}
        or score["scale"] != "0-100"
        or score["maturity"] not in {"optimized", "managed", "defined", "developing", "initial"}
        or any(isinstance(score[key], bool) or not isinstance(score[key], int) or not 0 <= score[key] <= 100 for key in ("value", "raw_value"))
    ):
        raise ReportDataError("report score is invalid")
    if not isinstance(report["suppressed_findings"], list):
        raise ReportDataError("suppressed_findings must be an array")
    suppressed_ids: set[str] = set()
    for item in report["suppressed_findings"]:
        _validate_finding(item, suppressed=True)
        if item["fingerprint"] in suppressed_ids:
            raise ReportDataError("report contains duplicate suppressed fingerprints")
        suppressed_ids.add(item["fingerprint"])
    if summary["total"] != len(report["findings"]) or summary["suppressed"] != len(report["suppressed_findings"]):
        raise ReportDataError("report summary counts do not match findings")
    actual_counts = {severity: 0 for severity in SEVERITY_ORDER}
    active = _findings(report)
    for finding in active:
        actual_counts[finding["severity"]] += 1
    if summary["by_severity"] != actual_counts:
        raise ReportDataError("report severity counts do not match findings")
    active_ids = {finding["fingerprint"] for finding in active}
    if active_ids.intersection(suppressed_ids):
        raise ReportDataError("active and suppressed findings overlap")

    state = report["state"]
    expected_status = "verified" if state == "DONE" else "blocked"
    if report["status"] != expected_status:
        raise ReportDataError("report state and status are inconsistent")
    valid_reasons = {
        "DONE": {"AUDIT_COMPLETE"},
        "DEGRADED": {"AUDIT_DEGRADED"},
        "WAITING": {"TIMEOUT", "FILE_LIMIT", "BYTE_LIMIT", "FINDING_LIMIT"},
        "REJECTED": {"ROOT_INVALID", "CIRCUIT_OPEN"},
    }
    if report["reason_code"] not in valid_reasons[state]:
        raise ReportDataError("report state and reason_code are inconsistent")
    if state == "DONE" and report["errors"]:
        raise ReportDataError("verified report cannot contain operational errors")
    if state == "DEGRADED" and not report["errors"]:
        raise ReportDataError("degraded report must contain an operational error")

    if any(finding["severity"] in {"critical", "high"} for finding in active):
        expected_result = "FAIL"
    elif active:
        expected_result = "WARN"
    else:
        expected_result = "PASS"
    if report["result"] != expected_result:
        raise ReportDataError("report result does not match active findings")

    active_penalty = sum(SEVERITY_PENALTY[finding["severity"]] for finding in active)
    suppressed_penalty = sum(
        SEVERITY_PENALTY[finding["severity"]] for finding in report["suppressed_findings"]
    )
    blocked_penalty = 0 if expected_status == "verified" else 20
    expected_value = max(0, 100 - active_penalty - blocked_penalty)
    expected_raw = max(0, 100 - active_penalty - suppressed_penalty - blocked_penalty)
    expected_maturity = (
        "optimized" if expected_value >= 90 else
        "managed" if expected_value >= 75 else
        "defined" if expected_value >= 55 else
        "developing" if expected_value >= 30 else
        "initial"
    )
    if (
        score["value"] != expected_value
        or score["raw_value"] != expected_raw
        or score["maturity"] != expected_maturity
    ):
        raise ReportDataError("report score does not match findings and audit status")
    for key, expected in (
        ("findings", len(active)),
        ("suppressed_findings", len(report["suppressed_findings"])),
        ("errors", len(report["errors"])),
    ):
        if key in report["metrics"] and report["metrics"][key] != expected:
            raise ReportDataError(f"report metric {key} is inconsistent")


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
