"""Composable, deterministic rule registry.

The registry is deliberately a Python API rather than a dynamic package loader: callers
explicitly opt in to trusted plugins, and scanning never imports code from the repository
being inspected.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import time
from typing import Callable, Iterable, Iterator

from .models import Finding, SEVERITY_ORDER
from .sanitization import is_safe_output_text, safe_output_text


RuleFunction = Callable[[tuple[object, ...]], Iterable[Finding]]
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")


class RegistryError(ValueError):
    """A rule plugin or one of its findings violates the registry contract."""


class RegistryDeadlineExceeded(TimeoutError):
    """The rule pass crossed the scanner deadline with a safe partial result."""

    def __init__(self, findings: list[Finding], executed: tuple[str, ...]):
        super().__init__("rule execution reached timeout_seconds")
        self.findings = findings
        self.executed = executed


class _DeadlineFiles(tuple[object, ...]):
    def __new__(
        cls,
        values: tuple[object, ...],
        deadline: float | None,
        clock: Callable[[], float],
    ) -> "_DeadlineFiles":
        instance = super().__new__(cls, values)
        instance.deadline = deadline
        instance.clock = clock
        return instance

    def __iter__(self) -> Iterator[object]:
        for value in super().__iter__():
            if self.deadline is not None and self.clock() >= self.deadline:
                raise RegistryDeadlineExceeded([], ())
            yield value


@dataclass(frozen=True)
class RulePlugin:
    name: str
    category: str
    description: str
    audit: RuleFunction

    def __post_init__(self) -> None:
        if not _SAFE_NAME.fullmatch(self.name):
            raise RegistryError("plugin name must be a safe 2-64 character identifier")
        if not _SAFE_NAME.fullmatch(self.category):
            raise RegistryError("plugin category must be a safe 2-64 character identifier")
        if not isinstance(self.description, str):
            raise RegistryError("plugin description must contain 1-300 characters")
        safe_description = safe_output_text(self.description)
        if not safe_description.strip() or len(safe_description) > 300:
            raise RegistryError("plugin description must contain 1-300 characters")
        if not callable(self.audit):
            raise RegistryError("plugin audit must be callable")
        object.__setattr__(self, "description", safe_description)


class RuleRegistry:
    """Ordered rule collection with explicit registration and result validation."""

    def __init__(self, plugins: Iterable[RulePlugin] = ()):
        self._plugins: dict[str, RulePlugin] = {}
        for plugin in plugins:
            self.register(plugin)

    def register(self, plugin: RulePlugin) -> "RuleRegistry":
        if plugin.name in self._plugins:
            raise RegistryError(f"duplicate plugin name: {plugin.name}")
        self._plugins[plugin.name] = plugin
        return self

    def clone(self) -> "RuleRegistry":
        return RuleRegistry(self.plugins)

    @property
    def plugins(self) -> tuple[RulePlugin, ...]:
        return tuple(self._plugins[name] for name in sorted(self._plugins))

    def run(
        self,
        files: tuple[object, ...],
        enabled_categories: Iterable[str],
        *,
        max_findings: int,
        deadline: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> tuple[list[Finding], tuple[str, ...], bool]:
        enabled = set(enabled_categories)
        findings: list[Finding] = []
        executed: list[str] = []
        bounded_files = _DeadlineFiles(files, deadline, clock)
        fingerprints: dict[str, Finding] = {}
        for plugin in self.plugins:
            if plugin.category not in enabled:
                continue
            if deadline is not None and clock() >= deadline:
                raise RegistryDeadlineExceeded(findings, tuple(executed))
            executed.append(plugin.name)
            try:
                produced = plugin.audit(bounded_files)
                if deadline is not None and clock() >= deadline:
                    raise RegistryDeadlineExceeded(findings, tuple(executed))
                for finding in produced:
                    if deadline is not None and clock() >= deadline:
                        raise RegistryDeadlineExceeded(findings, tuple(executed))
                    self._validate_finding(plugin, finding)
                    existing = fingerprints.get(finding.fingerprint)
                    if existing is not None:
                        if existing == finding:
                            continue
                        raise RegistryError(
                            f"plugin {plugin.name} returned a conflicting duplicate fingerprint"
                        )
                    fingerprints[finding.fingerprint] = finding
                    findings.append(finding)
                    if len(findings) > max_findings:
                        return findings[:max_findings], tuple(executed), True
            except RegistryDeadlineExceeded as exc:
                if exc.findings:
                    raise
                raise RegistryDeadlineExceeded(findings, tuple(executed)) from None
        return findings, tuple(executed), False

    @staticmethod
    def _validate_finding(plugin: RulePlugin, finding: Finding) -> None:
        if not isinstance(finding, Finding):
            raise RegistryError(f"plugin {plugin.name} returned a non-Finding value")
        if finding.category != plugin.category:
            raise RegistryError(
                f"plugin {plugin.name} returned category {finding.category!r}, expected {plugin.category!r}"
            )
        if finding.severity not in SEVERITY_ORDER:
            raise RegistryError(f"plugin {plugin.name} returned unknown severity: {finding.severity}")
        if finding.classification not in {"proof", "inference", "blockage"}:
            raise RegistryError(
                f"plugin {plugin.name} returned unknown classification: {finding.classification}"
            )
        if not isinstance(finding.code, str) or not _SAFE_CODE.fullmatch(finding.code):
            raise RegistryError(f"plugin {plugin.name} returned an invalid diagnostic code")
        for value, label, maximum in (
            (finding.message, "message", 2_000),
            (finding.remediation, "remediation", 2_000),
        ):
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value.encode("utf-8")) > maximum
                or not is_safe_output_text(value)
            ):
                raise RegistryError(f"plugin {plugin.name} returned an invalid {label}")
        if finding.evidence is not None and (
            not isinstance(finding.evidence, str)
            or len(finding.evidence.encode("utf-8")) > 4_096
            or not is_safe_output_text(finding.evidence)
        ):
            raise RegistryError(f"plugin {plugin.name} returned invalid evidence")
        if finding.path is not None:
            if (
                not isinstance(finding.path, str)
                or not finding.path
                or len(finding.path.encode("utf-8")) > 1_024
                or not is_safe_output_text(finding.path)
            ):
                raise RegistryError(f"plugin {plugin.name} returned an invalid path")
            normalized = finding.path.replace("\\", "/")
            path = PurePosixPath(normalized)
            if path.is_absolute() or ".." in path.parts:
                raise RegistryError(f"plugin {plugin.name} returned an escaping path")
        if finding.line is not None and (
            isinstance(finding.line, bool)
            or not isinstance(finding.line, int)
            or not 1 <= finding.line <= 2**31 - 1
        ):
            raise RegistryError(f"plugin {plugin.name} returned an invalid line")

    def as_dict(self) -> list[dict[str, str]]:
        return [
            {"name": plugin.name, "category": plugin.category, "description": plugin.description}
            for plugin in self.plugins
        ]
