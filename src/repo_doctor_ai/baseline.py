"""Reviewed finding baselines with mandatory reasons and optional expiry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .models import Finding, SuppressedFinding
from .io_utils import BoundedReadError, read_bounded_text
from .sanitization import safe_output_text

MAX_BASELINE_BYTES = 4 * 1024 * 1024
BASELINE_SCHEMA = "repo-doctor-baseline/1"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class BaselineError(ValueError):
    """A baseline is malformed, unsafe, or incompatible."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _invalid_constant(value: str) -> None:
    raise BaselineError(f"non-finite JSON number is not allowed: {value}")


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    code: str
    reason: str
    expires: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "BaselineEntry":
        if not isinstance(raw, dict) or set(raw) != {"fingerprint", "code", "reason", "expires"}:
            raise BaselineError("baseline entry must contain fingerprint, code, reason, and expires")
        fingerprint = raw["fingerprint"]
        code = raw["code"]
        reason = raw["reason"]
        expires = raw["expires"]
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{20}", fingerprint):
            raise BaselineError("baseline fingerprint must be 20 lowercase hex characters")
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code):
            raise BaselineError("baseline code is invalid")
        if not isinstance(reason, str) or not 8 <= len(reason.strip()) <= 500:
            raise BaselineError("baseline reason must contain 8-500 characters")
        safe_reason = safe_output_text(reason.strip())
        if not 8 <= len(safe_reason) <= 500:
            raise BaselineError("sanitized baseline reason must contain 8-500 characters")
        if expires is not None:
            if not isinstance(expires, str) or not DATE_RE.fullmatch(expires):
                raise BaselineError("baseline expiry must be YYYY-MM-DD or null")
            try:
                date.fromisoformat(expires)
            except ValueError as exc:
                raise BaselineError("baseline expiry must be YYYY-MM-DD or null") from exc
        return cls(fingerprint, code, safe_reason, expires)

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "code": self.code,
            "reason": self.reason,
            "expires": self.expires,
        }


@dataclass(frozen=True)
class Baseline:
    entries: tuple[BaselineEntry, ...]
    source_report_sha256: str

    @classmethod
    def from_dict(cls, raw: Any) -> "Baseline":
        required = {"schema", "source_report_sha256", "entries"}
        if not isinstance(raw, dict) or set(raw) != required:
            raise BaselineError("baseline root must contain schema, source_report_sha256, and entries")
        if raw["schema"] != BASELINE_SCHEMA:
            raise BaselineError(f"baseline schema must be {BASELINE_SCHEMA}")
        digest = raw["source_report_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BaselineError("source_report_sha256 must be 64 lowercase hex characters")
        values = raw["entries"]
        if not isinstance(values, list) or len(values) > 100_000:
            raise BaselineError("baseline entries must be an array of at most 100000 items")
        entries = tuple(BaselineEntry.from_dict(value) for value in values)
        identities = [entry.fingerprint for entry in entries]
        if len(set(identities)) != len(identities):
            raise BaselineError("baseline contains duplicate fingerprints")
        return cls(tuple(sorted(entries, key=lambda entry: (entry.code, entry.fingerprint))), digest)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": BASELINE_SCHEMA,
            "source_report_sha256": self.source_report_sha256,
            "entries": [entry.as_dict() for entry in self.entries],
        }

    def apply(
        self,
        findings: Iterable[Finding],
        *,
        today: date | None = None,
    ) -> tuple[tuple[Finding, ...], tuple[SuppressedFinding, ...], tuple[BaselineEntry, ...]]:
        current = today or date.today()
        by_fingerprint = {entry.fingerprint: entry for entry in self.entries}
        active: list[Finding] = []
        suppressed: list[SuppressedFinding] = []
        expired: list[BaselineEntry] = []
        for finding in findings:
            entry = by_fingerprint.get(finding.fingerprint)
            if entry is None or entry.code != finding.code:
                active.append(finding)
                continue
            if entry.expires is not None and date.fromisoformat(entry.expires) < current:
                active.append(finding)
                expired.append(entry)
                continue
            suppressed.append(SuppressedFinding(finding, entry.reason, entry.expires))
        return tuple(active), tuple(suppressed), tuple(expired)


def load_baseline(path: str | Path) -> Baseline:
    baseline_path = Path(path)
    try:
        text = read_bounded_text(baseline_path, MAX_BASELINE_BYTES, label="baseline")
        raw = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except BaselineError:
        raise
    except (BoundedReadError, json.JSONDecodeError) as exc:
        raise BaselineError(f"invalid baseline: {exc}") from exc
    return Baseline.from_dict(raw)


def baseline_from_report(
    report: Any,
    *,
    reason: str,
    expires: str | None = None,
) -> Baseline:
    from .diffing import validate_report

    validate_report(report)
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise BaselineError("input must be a Repo Doctor JSON report")
    if not isinstance(reason, str) or not 8 <= len(reason.strip()) <= 500:
        raise BaselineError("baseline reason must contain 8-500 characters")
    safe_reason = safe_output_text(reason.strip())
    if not 8 <= len(safe_reason) <= 500:
        raise BaselineError("sanitized baseline reason must contain 8-500 characters")
    if expires is not None:
        if not isinstance(expires, str) or not DATE_RE.fullmatch(expires):
            raise BaselineError("baseline expiry must be YYYY-MM-DD or null")
        try:
            date.fromisoformat(expires)
        except ValueError as exc:
            raise BaselineError("baseline expiry must be YYYY-MM-DD or null") from exc
    entries: list[BaselineEntry] = []
    for raw in report["findings"]:
        if not isinstance(raw, dict):
            raise BaselineError("report finding must be an object")
        entries.append(
            BaselineEntry.from_dict(
                {
                    "fingerprint": raw.get("fingerprint"),
                    "code": raw.get("code"),
                    "reason": safe_reason,
                    "expires": expires,
                }
            )
        )
    digest = hashlib.sha256(_canonical(report)).hexdigest()
    return Baseline.from_dict(
        {"schema": BASELINE_SCHEMA, "source_report_sha256": digest, "entries": [entry.as_dict() for entry in entries]}
    )
