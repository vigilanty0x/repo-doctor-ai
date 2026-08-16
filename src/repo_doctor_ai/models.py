"""Stable report model, scoring, and diagnostic vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .sanitization import safe_output_text, sanitize_json_value

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_PENALTY = {"info": 0, "low": 2, "medium": 5, "high": 12, "critical": 25}


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

    def __post_init__(self) -> None:
        # Findings are the common source for every renderer and persisted report.
        # Enforce the output boundary once so a non-secret rule or trusted plugin
        # cannot accidentally re-emit a credential detected elsewhere.
        for field in (
            "code",
            "category",
            "severity",
            "classification",
            "message",
            "remediation",
            "path",
            "evidence",
        ):
            value = getattr(self, field)
            if isinstance(value, str):
                object.__setattr__(self, field, safe_output_text(value))

    @property
    def fingerprint(self) -> str:
        identity = {
            "code": self.code,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
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
class SuppressedFinding:
    """A finding matched by a reviewed, optionally expiring baseline entry."""

    finding: Finding
    reason: str
    expires: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.finding.as_dict(),
            "suppression": {
                "reason": safe_output_text(self.reason),
                "expires": safe_output_text(self.expires) if isinstance(self.expires, str) else self.expires,
            },
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
    suppressed_findings: tuple[SuppressedFinding, ...] = ()

    @property
    def quality_score(self) -> int:
        """Return a deterministic 0-100 score for active findings."""

        penalty = sum(SEVERITY_PENALTY[finding.severity] for finding in self.findings)
        if self.status != "verified":
            penalty += 20
        return max(0, 100 - penalty)

    @property
    def raw_quality_score(self) -> int:
        """Return the score before baseline suppressions are applied."""

        penalty = sum(SEVERITY_PENALTY[finding.severity] for finding in self.findings)
        penalty += sum(SEVERITY_PENALTY[item.finding.severity] for item in self.suppressed_findings)
        if self.status != "verified":
            penalty += 20
        return max(0, 100 - penalty)

    @property
    def maturity(self) -> str:
        score = self.quality_score
        if score >= 90:
            return "optimized"
        if score >= 75:
            return "managed"
        if score >= 55:
            return "defined"
        if score >= 30:
            return "developing"
        return "initial"

    def as_dict(self) -> dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "report_version": "2.0",
            "root": safe_output_text(self.root),
            "state": safe_output_text(self.state),
            "status": safe_output_text(self.status),
            "result": safe_output_text(self.result),
            "reason_code": safe_output_text(self.reason_code),
            "summary": {
                "total": len(self.findings),
                "suppressed": len(self.suppressed_findings),
                "by_severity": counts,
            },
            "score": {
                "value": self.quality_score,
                "raw_value": self.raw_quality_score,
                "maturity": self.maturity,
                "scale": "0-100",
            },
            "metrics": sanitize_json_value(dict(sorted(self.metrics.items()))),
            "errors": [safe_output_text(error) for error in self.errors],
            "findings": [finding.as_dict() for finding in self.findings],
            "suppressed_findings": [item.as_dict() for item in self.suppressed_findings],
        }

    def reaches(self, severity: str) -> bool:
        threshold = SEVERITY_ORDER[severity]
        return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in self.findings)
