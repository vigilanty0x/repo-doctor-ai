"""Strict scanner configuration."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any

from .io_utils import BoundedReadError, read_bounded_text

CATEGORIES = (
    "structure",
    "tests",
    "ci",
    "dependencies",
    "secrets",
    "todos",
    "debt",
    "repository",
    "ownership",
    "documentation",
    "release",
)
DEFAULT_EXCLUDES = (
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
)
MAX_CONFIG_BYTES = 1024 * 1024
_SAFE_CATEGORY = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class ConfigError(ValueError):
    """Configuration is malformed or outside safe bounds."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ConfigError(f"non-finite JSON number is not allowed: {value}")


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


@dataclass(frozen=True)
class Config:
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    max_files: int = 10_000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    timeout_seconds: int = 30
    error_threshold: int = 20
    max_findings: int = 5_000
    enabled_categories: tuple[str, ...] = CATEGORIES

    def __post_init__(self) -> None:
        if isinstance(self.exclude, str):
            raise ConfigError("exclude must be a sequence of path strings")
        if isinstance(self.enabled_categories, str):
            raise ConfigError("enabled_categories must be a sequence of identifiers")
        try:
            excludes = tuple(self.exclude)
            categories = tuple(self.enabled_categories)
        except TypeError as exc:
            raise ConfigError("configuration collections must be iterable") from exc
        if (
            len(excludes) > 256
            or any(not isinstance(item, str) or not item or len(item) > 256 for item in excludes)
        ):
            raise ConfigError("exclude must contain at most 256 non-empty strings")
        for item in excludes:
            if item.startswith(("/", "\\")) or ".." in Path(item.replace("\\", "/")).parts:
                raise ConfigError("exclude entries must be safe relative names or paths")
        if len(set(excludes)) != len(excludes):
            raise ConfigError("exclude contains duplicates")

        if (
            not categories
            or len(categories) > 256
            or any(not isinstance(category, str) or not _SAFE_CATEGORY.fullmatch(category) for category in categories)
        ):
            raise ConfigError("enabled_categories must contain safe 2-64 character identifiers")
        if len(set(categories)) != len(categories):
            raise ConfigError("enabled_categories contains duplicates")

        _integer(self.max_files, "max_files", 1, 1_000_000)
        _integer(self.max_file_bytes, "max_file_bytes", 1024, 64 * 1024 * 1024)
        _integer(self.max_total_bytes, "max_total_bytes", 1024, 4 * 1024 * 1024 * 1024)
        _integer(self.timeout_seconds, "timeout_seconds", 1, 3600)
        _integer(self.error_threshold, "error_threshold", 1, 10_000)
        _integer(self.max_findings, "max_findings", 1, 100_000)
        object.__setattr__(self, "exclude", excludes)
        object.__setattr__(self, "enabled_categories", categories)

    @classmethod
    def from_dict(cls, raw: Any) -> "Config":
        if not isinstance(raw, dict):
            raise ConfigError("configuration root must be an object")
        allowed = {
            "config_version",
            "exclude",
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "timeout_seconds",
            "error_threshold",
            "max_findings",
            "enabled_categories",
        }
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ConfigError(f"unknown configuration fields: {', '.join(unknown)}")
        if raw.get("config_version", "1.0") != "1.0":
            raise ConfigError("config_version must be '1.0'")

        excludes = raw.get("exclude", list(DEFAULT_EXCLUDES))
        if (
            not isinstance(excludes, list)
            or len(excludes) > 256
            or any(not isinstance(item, str) or not item or len(item) > 256 for item in excludes)
        ):
            raise ConfigError("exclude must be an array of at most 256 non-empty strings")
        for item in excludes:
            if item.startswith(("/", "\\")) or ".." in Path(item.replace("\\", "/")).parts:
                raise ConfigError("exclude entries must be safe relative names or paths")

        categories = raw.get("enabled_categories", list(CATEGORIES))
        if not isinstance(categories, list) or not categories:
            raise ConfigError("enabled_categories must be a non-empty array")
        if any(category not in CATEGORIES for category in categories):
            raise ConfigError("enabled_categories contains an unknown category")
        if len(set(categories)) != len(categories):
            raise ConfigError("enabled_categories contains duplicates")

        return cls(
            exclude=tuple(excludes),
            max_files=_integer(raw.get("max_files", 10_000), "max_files", 1, 1_000_000),
            max_file_bytes=_integer(raw.get("max_file_bytes", 1024 * 1024), "max_file_bytes", 1024, 64 * 1024 * 1024),
            max_total_bytes=_integer(
                raw.get("max_total_bytes", 64 * 1024 * 1024),
                "max_total_bytes",
                1024,
                4 * 1024 * 1024 * 1024,
            ),
            timeout_seconds=_integer(raw.get("timeout_seconds", 30), "timeout_seconds", 1, 3600),
            error_threshold=_integer(raw.get("error_threshold", 20), "error_threshold", 1, 10_000),
            max_findings=_integer(raw.get("max_findings", 5_000), "max_findings", 1, 100_000),
            enabled_categories=tuple(categories),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "config_version": "1.0",
            "exclude": list(self.exclude),
            "max_files": self.max_files,
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
            "timeout_seconds": self.timeout_seconds,
            "error_threshold": self.error_threshold,
            "max_findings": self.max_findings,
            "enabled_categories": list(self.enabled_categories),
        }


def load_config(path: str | Path | None) -> Config:
    if path is None:
        return Config()
    config_path = Path(path)
    try:
        text = read_bounded_text(config_path, MAX_CONFIG_BYTES, label="configuration")
        raw = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except ConfigError:
        raise
    except (BoundedReadError, json.JSONDecodeError) as exc:
        raise ConfigError(f"invalid configuration: {exc}") from exc
    return Config.from_dict(raw)
