"""Final output sanitization shared by reports, journals, and inventories."""

from __future__ import annotations

import re
from typing import Any


_CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{30,}"),
        "[REDACTED:GITHUB_TOKEN]",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,}"),
        "[REDACTED:GITHUB_TOKEN]",
    ),
    (
        re.compile(r"(?<![0-9A-Z])AKIA[0-9A-Z]{16}(?![0-9A-Z])"),
        "[REDACTED:AWS_ACCESS_KEY]",
    ),
)
_URL_CREDENTIAL = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<user>[^\s/:@]+):(?P<secret>[^\s/@]+)@"
)
_QUOTED_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
    r"\b\s*[:=]\s*)(?P<value>'[^'\r\n]{12,}'|\"[^\"\r\n]{12,}\")"
)
_UNQUOTED_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
    r"\b\s*[:=]\s*)(?P<value>[^\s,;}]{12,})"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----.*?"
    r"-----END (?P=kind)-----",
    re.DOTALL,
)
_PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")


def redact_credentials(value: str) -> str:
    """Remove common credential material without echoing the matched value."""

    redacted = _PRIVATE_KEY_BLOCK.sub("[REDACTED:PRIVATE_KEY]", value)
    redacted = _PRIVATE_KEY_HEADER.sub("[REDACTED:PRIVATE_KEY]", redacted)
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    redacted = _URL_CREDENTIAL.sub(
        lambda match: f"{match.group('scheme')}{match.group('user')}:[REDACTED]@",
        redacted,
    )
    redacted = _QUOTED_ASSIGNMENT.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('value')[0]}"
            f"[REDACTED]{match.group('value')[-1]}"
        ),
        redacted,
    )
    redacted = _UNQUOTED_ASSIGNMENT.sub(
        lambda match: f"{match.group('prefix')}[REDACTED]",
        redacted,
    )
    return redacted


def neutralize_controls(value: str) -> str:
    """Render C0/C1 controls visibly so terminal and line-oriented formats stay inert."""

    pieces: list[str] = []
    for character in value:
        number = ord(character)
        if number < 32 or 127 <= number <= 159:
            escapes = {9: "\\t", 10: "\\n", 13: "\\r"}
            pieces.append(escapes.get(number, f"\\x{number:02x}"))
        else:
            pieces.append(character)
    return "".join(pieces)


def safe_output_text(value: str) -> str:
    """Apply the mandatory final credential and control-character policy."""

    return neutralize_controls(redact_credentials(value))


def sanitize_json_value(value: Any) -> Any:
    """Recursively sanitize every string position in a strict JSON-compatible value."""

    if isinstance(value, str):
        return safe_output_text(value)
    if isinstance(value, list):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            safe_key = safe_output_text(key) if isinstance(key, str) else key
            if safe_key in result:
                raise ValueError("sanitization produced duplicate JSON keys")
            result[safe_key] = sanitize_json_value(item)
        return result
    return value


def is_safe_output_text(value: str) -> bool:
    return safe_output_text(value) == value
