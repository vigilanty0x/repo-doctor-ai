"""Deterministic, evidence-first repository audit rules."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import Callable, Iterable

from .models import Finding


@dataclass(frozen=True)
class SourceFile:
    path: str
    size: int
    text: str | None


RULE_HELP: dict[str, str] = {
    "STRUCTURE_README_MISSING": "No README file was found at the repository root.",
    "STRUCTURE_LICENSE_MISSING": "No common license file was found at the repository root.",
    "STRUCTURE_SECURITY_MISSING": "No SECURITY.md policy was found.",
    "STRUCTURE_CONTRIBUTING_MISSING": "No CONTRIBUTING.md guide was found.",
    "TESTS_MISSING": "No recognized test file or test directory was found.",
    "CI_MISSING": "No GitHub Actions workflow was found.",
    "CI_PULL_REQUEST_TARGET": "A workflow uses pull_request_target, which requires careful privilege review.",
    "CI_ACTION_FLOATING_REF": "A workflow action uses a moving branch or latest tag.",
    "DEPENDENCY_UNPINNED": "A dependency declaration is not exactly pinned.",
    "SECRET_PRIVATE_KEY": "A private-key header was detected; matched content is never emitted.",
    "SECRET_GITHUB_TOKEN": "A GitHub token-shaped value was detected; matched content is never emitted.",
    "SECRET_AWS_ACCESS_KEY": "An AWS access-key-shaped value was detected; matched content is never emitted.",
    "SECRET_GENERIC_ASSIGNMENT": "A credential-like assignment with a long literal value was detected.",
    "TODO_MARKER": "A TODO or FIXME marker records unfinished work.",
    "DEBT_BARE_EXCEPT": "A Python bare except may hide unexpected failures.",
    "DEBT_DYNAMIC_EXEC": "Dynamic eval or exec increases review and injection risk.",
    "DEBT_LARGE_SOURCE": "A source file exceeds 1000 lines and may need decomposition.",
}


def _finding(
    code: str,
    category: str,
    severity: str,
    message: str,
    remediation: str,
    *,
    path: str | None = None,
    line: int | None = None,
    evidence: str | None = None,
    classification: str = "proof",
) -> Finding:
    return Finding(code, category, severity, classification, message, remediation, path, line, evidence)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def audit_structure(files: tuple[SourceFile, ...]) -> list[Finding]:
    root_names = {PurePosixPath(file.path).name.lower() for file in files if "/" not in file.path}
    findings: list[Finding] = []
    requirements = (
        ({"readme", "readme.md", "readme.rst", "readme.txt"}, "STRUCTURE_README_MISSING", "medium", "Add a root README with install and usage instructions."),
        ({"license", "license.md", "license.txt", "copying"}, "STRUCTURE_LICENSE_MISSING", "medium", "Add an explicit open-source license file."),
        ({"security.md"}, "STRUCTURE_SECURITY_MISSING", "low", "Document supported versions and private vulnerability reporting."),
        ({"contributing.md"}, "STRUCTURE_CONTRIBUTING_MISSING", "low", "Document the development and review workflow."),
    )
    for candidates, code, severity, remediation in requirements:
        if not root_names.intersection(candidates):
            findings.append(_finding(code, "structure", severity, RULE_HELP[code], remediation, evidence="root file inventory"))
    return findings


def audit_tests(files: tuple[SourceFile, ...]) -> list[Finding]:
    recognized = False
    for file in files:
        path = PurePosixPath(file.path)
        name = path.name.lower()
        parts = {part.lower() for part in path.parts}
        if (
            "tests" in parts
            or "test" in parts
            or name.startswith("test_")
            or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
        ):
            recognized = True
            break
    if recognized:
        return []
    return [
        _finding(
            "TESTS_MISSING",
            "tests",
            "high",
            RULE_HELP["TESTS_MISSING"],
            "Add executable tests and document their command.",
            evidence=f"scanned {len(files)} files",
        )
    ]


def audit_ci(files: tuple[SourceFile, ...]) -> list[Finding]:
    workflows = [
        file
        for file in files
        if file.path.startswith(".github/workflows/") and file.path.lower().endswith((".yml", ".yaml"))
    ]
    if not workflows:
        return [
            _finding(
                "CI_MISSING",
                "ci",
                "medium",
                RULE_HELP["CI_MISSING"],
                "Add a least-privilege workflow that runs tests on pull requests.",
                evidence=".github/workflows inventory",
            )
        ]
    findings: list[Finding] = []
    floating = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*[^\s#]+@(main|master|latest)\s*(?:#.*)?$")
    target = re.compile(r"(?m)^\s*pull_request_target\s*:")
    for file in workflows:
        if file.text is None:
            continue
        for match in target.finditer(file.text):
            findings.append(
                _finding(
                    "CI_PULL_REQUEST_TARGET",
                    "ci",
                    "high",
                    RULE_HELP["CI_PULL_REQUEST_TARGET"],
                    "Use pull_request when possible; otherwise isolate untrusted checkout and minimize permissions.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence="workflow trigger: pull_request_target",
                )
            )
        for match in floating.finditer(file.text):
            findings.append(
                _finding(
                    "CI_ACTION_FLOATING_REF",
                    "ci",
                    "medium",
                    RULE_HELP["CI_ACTION_FLOATING_REF"],
                    "Pin third-party actions to a reviewed commit SHA.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence=f"moving ref: {match.group(1)}",
                )
            )
    return findings


def _requirement_findings(file: SourceFile) -> Iterable[Finding]:
    if file.text is None:
        return
    for number, raw in enumerate(file.text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", "-e ", "--")):
            continue
        package = re.split(r"[;\s]", line, maxsplit=1)[0]
        if "==" not in package and " @ " not in line:
            yield _finding(
                "DEPENDENCY_UNPINNED",
                "dependencies",
                "medium",
                RULE_HELP["DEPENDENCY_UNPINNED"],
                "Pin direct dependencies and update them through reviewed automation.",
                path=file.path,
                line=number,
                evidence="requirement without exact version",
            )


def audit_dependencies(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        name = PurePosixPath(file.path).name.lower()
        if name in {"requirements.txt", "requirements-dev.txt", "constraints.txt"}:
            findings.extend(_requirement_findings(file))
        elif name == "pyproject.toml" and file.text is not None:
            try:
                document = tomllib.loads(file.text)
            except tomllib.TOMLDecodeError:
                continue
            dependencies = document.get("project", {}).get("dependencies", [])
            if isinstance(dependencies, list):
                for dependency in dependencies:
                    if isinstance(dependency, str) and "==" not in dependency and " @ " not in dependency:
                        findings.append(
                            _finding(
                                "DEPENDENCY_UNPINNED",
                                "dependencies",
                                "low",
                                RULE_HELP["DEPENDENCY_UNPINNED"],
                                "Use a lock or constraints file for applications; libraries may document a compatible range.",
                                path=file.path,
                                evidence=f"project dependency: {dependency.split()[0][:80]}",
                                classification="inference",
                            )
                        )
        elif name == "package.json" and file.text is not None:
            try:
                document = json.loads(file.text)
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies"):
                values = document.get(section, {})
                if isinstance(values, dict):
                    for package, version in values.items():
                        if version in {"*", "latest"}:
                            findings.append(
                                _finding(
                                    "DEPENDENCY_UNPINNED",
                                    "dependencies",
                                    "medium",
                                    RULE_HELP["DEPENDENCY_UNPINNED"],
                                    "Declare a bounded version and commit the package-manager lockfile.",
                                    path=file.path,
                                    evidence=f"{section} entry {str(package)[:80]} uses a moving version",
                                )
                            )
    return findings


SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("SECRET_PRIVATE_KEY", "critical", re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SECRET_GITHUB_TOKEN", "critical", re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}")),
    ("SECRET_AWS_ACCESS_KEY", "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "SECRET_GENERIC_ASSIGNMENT",
        "high",
        re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"\r\n]{12,}['\"]"),
    ),
)


def audit_secrets(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if file.text is None:
            continue
        for code, severity, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(file.text):
                findings.append(
                    _finding(
                        code,
                        "secrets",
                        severity,
                        RULE_HELP[code],
                        "Revoke the value, remove it from history, and load credentials from a secret store.",
                        path=file.path,
                        line=_line_number(file.text, match.start()),
                        evidence=f"redacted credential-shaped match ({len(match.group(0))} characters)",
                    )
                )
    return findings


def audit_todos(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(?i)\b(TODO|FIXME)\b")
    for file in files:
        if file.text is None:
            continue
        for index, match in enumerate(pattern.finditer(file.text)):
            if index >= 50:
                break
            findings.append(
                _finding(
                    "TODO_MARKER",
                    "todos",
                    "low",
                    RULE_HELP["TODO_MARKER"],
                    "Link the marker to a tracked issue or resolve it.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence=f"marker: {match.group(1).upper()}",
                )
            )
    return findings


def audit_debt(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    bare_except = re.compile(r"(?m)^\s*except\s*:\s*(?:#.*)?$")
    dynamic = re.compile(r"\b(eval|exec)\s*\(")
    for file in files:
        if file.text is None or not file.path.endswith(".py"):
            continue
        lines = file.text.count("\n") + 1
        if lines > 1000:
            findings.append(
                _finding(
                    "DEBT_LARGE_SOURCE",
                    "debt",
                    "medium",
                    RULE_HELP["DEBT_LARGE_SOURCE"],
                    "Split responsibilities while preserving tests and public interfaces.",
                    path=file.path,
                    evidence=f"{lines} lines",
                )
            )
        for match in bare_except.finditer(file.text):
            findings.append(
                _finding(
                    "DEBT_BARE_EXCEPT",
                    "debt",
                    "medium",
                    RULE_HELP["DEBT_BARE_EXCEPT"],
                    "Catch the narrow expected exception and preserve unexpected failures.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence="bare except clause",
                )
            )
        for match in dynamic.finditer(file.text):
            findings.append(
                _finding(
                    "DEBT_DYNAMIC_EXEC",
                    "debt",
                    "high",
                    RULE_HELP["DEBT_DYNAMIC_EXEC"],
                    "Replace dynamic execution with a bounded parser or explicit dispatch table.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence=f"dynamic call: {match.group(1)}",
                )
            )
    return findings


AUDITORS: dict[str, Callable[[tuple[SourceFile, ...]], list[Finding]]] = {
    "structure": audit_structure,
    "tests": audit_tests,
    "ci": audit_ci,
    "dependencies": audit_dependencies,
    "secrets": audit_secrets,
    "todos": audit_todos,
    "debt": audit_debt,
}
