"""Stable report model and diagnostic vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    code: str
    category: str
    severity: str
    classification: str
    message: str
    remediation: str
    path: str | None = None
    line: int | None = None
    evidence: str | None = None

    @property
    def fingerprint(self) -> str:
        identity = {
            "code": self.code,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:20]

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "code": self.code,
            "category": self.category,
            "severity": self.severity,
            "classification": self.classification,
            "message": self.message,
            "remediation": self.remediation,
            "location": {"path": self.path, "line": self.line} if self.path else None,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Report:
    root: str
    state: str
    status: str
    result: str
    reason_code: str
    findings: tuple[Finding, ...]
    metrics: dict[str, int]
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "report_version": "1.0",
            "root": self.root,
            "state": self.state,
            "status": self.status,
            "result": self.result,
            "reason_code": self.reason_code,
            "summary": {"total": len(self.findings), "by_severity": counts},
            "metrics": dict(sorted(self.metrics.items())),
            "errors": list(self.errors),
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def reaches(self, severity: str) -> bool:
        threshold = SEVERITY_ORDER[severity]
        return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in self.findings)

