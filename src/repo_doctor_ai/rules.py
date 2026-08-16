"""Deterministic, evidence-first repository audit rules."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import io
import json
import math
from pathlib import PurePosixPath
import re
import tomllib
import tokenize
from typing import Callable, Iterable

from .models import Finding


@dataclass(frozen=True)
class SourceFile:
    path: str
    size: int
    text: str | None


RULE_HELP: dict[str, str] = {
    "SCAN_PATH_ESCAPE": "A resolved file path escaped the selected audit root.",
    "SCAN_SYMLINK_SKIPPED": "A file symlink was skipped to preserve the audit boundary.",
    "SCAN_FILE_SKIPPED_LARGE": "A file exceeded the configured content limit and was not inspected.",
    "SCAN_FILE_UNREADABLE": "A repository file could not be read completely.",
    "STRUCTURE_README_MISSING": "No README file was found at the repository root.",
    "STRUCTURE_LICENSE_MISSING": "No common license file was found at the repository root.",
    "STRUCTURE_SECURITY_MISSING": "No SECURITY.md policy was found.",
    "STRUCTURE_CONTRIBUTING_MISSING": "No CONTRIBUTING.md guide was found.",
    "TESTS_MISSING": "No recognized test file or test directory was found.",
    "CI_MISSING": "No GitHub Actions workflow was found.",
    "CI_PULL_REQUEST_TARGET": "A workflow uses pull_request_target, which requires careful privilege review.",
    "CI_ACTION_FLOATING_REF": "A workflow action uses a moving branch or latest tag.",
    "CI_ACTION_NOT_FULL_SHA": "A remote workflow action is not pinned to a full commit SHA.",
    "CI_PERMISSIONS_MISSING": "A workflow with jobs has no explicit least-privilege permissions block.",
    "CI_PERMISSION_WRITE": "A workflow grants a write permission that requires review.",
    "CI_UNTRUSTED_INTERPOLATION": "Event-controlled GitHub context is interpolated directly into a shell command.",
    "DEPENDENCY_UNPINNED": "A dependency declaration is not exactly pinned.",
    "DEPENDENCY_MANIFEST_INVALID": "A dependency manifest could not be parsed deterministically.",
    "DEPENDENCY_LOCK_MISSING": "A dependency manifest has no recognized lock or checksum file.",
    "DOCKER_BASE_UNPINNED": "A Docker base image is not pinned to an immutable digest.",
    "SECRET_PRIVATE_KEY": "A private-key header was detected; matched content is never emitted.",
    "SECRET_GITHUB_TOKEN": "A GitHub token-shaped value was detected; matched content is never emitted.",
    "SECRET_AWS_ACCESS_KEY": "An AWS access-key-shaped value was detected; matched content is never emitted.",
    "SECRET_GENERIC_ASSIGNMENT": "A credential-like assignment with a long literal value was detected.",
    "SECRET_HIGH_ENTROPY": "A credential-named assignment contains a high-entropy literal.",
    "TODO_MARKER": "A TODO or FIXME marker records unfinished work.",
    "DEBT_BARE_EXCEPT": "A Python bare except may hide unexpected failures.",
    "DEBT_DYNAMIC_EXEC": "Dynamic eval or exec increases review and injection risk.",
    "DEBT_LARGE_SOURCE": "A source file exceeds 1000 lines and may need decomposition.",
    "REPOSITORY_GENERATED_TRACKED": "A generated artifact appears to be tracked in the repository.",
    "REPOSITORY_VENDOR_TRACKED": "Vendored source appears to be tracked and needs an explicit update policy.",
    "REPOSITORY_LARGE_FILE": "A repository file exceeds the review-friendly size policy.",
    "OWNERSHIP_CODEOWNERS_MISSING": "No CODEOWNERS file defines review ownership.",
    "OWNERSHIP_MAINTAINERS_MISSING": "No maintainers or governance document was found.",
    "DOCUMENTATION_ARCHITECTURE_MISSING": "No architecture document was found.",
    "DOCUMENTATION_OPERATIONS_MISSING": "No operations, runbook, or deployment guide was found.",
    "RELEASE_CHANGELOG_MISSING": "No changelog or release-notes file was found.",
    "RELEASE_VERSION_MISMATCH": "Declared project versions disagree across manifests.",
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
    action = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*['\"]?([^\s#@'\"]+)@([^\s#'\"]+)['\"]?\s*(?:#.*)?$")
    docker_action_tag = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*['\"]?docker://[^\s#@'\"]+['\"]?\s*(?:#.*)?$")
    target = re.compile(r"(?m)^\s*pull_request_target\s*:")
    write_permission = re.compile(r"(?m)^\s*[a-z][a-z-]*:\s*write(?:-all)?\s*(?:#.*)?$")
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
        if re.search(r"(?m)^jobs\s*:", file.text) and not re.search(r"(?m)^permissions\s*:", file.text):
            findings.append(
                _finding(
                    "CI_PERMISSIONS_MISSING",
                    "ci",
                    "medium",
                    RULE_HELP["CI_PERMISSIONS_MISSING"],
                    "Declare top-level permissions, normally `contents: read`, and elevate only per job.",
                    path=file.path,
                    evidence="workflow jobs without top-level permissions",
                )
            )
        for match in write_permission.finditer(file.text):
            findings.append(
                _finding(
                    "CI_PERMISSION_WRITE",
                    "ci",
                    "medium",
                    RULE_HELP["CI_PERMISSION_WRITE"],
                    "Keep top-level permissions read-only and grant reviewed write scopes only to the job that needs them.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence="explicit workflow write permission",
                )
            )
        for line in _untrusted_shell_interpolation_lines(file.text):
            findings.append(
                _finding(
                    "CI_UNTRUSTED_INTERPOLATION",
                    "ci",
                    "high",
                    RULE_HELP["CI_UNTRUSTED_INTERPOLATION"],
                    "Pass event data through a quoted environment variable and validate it before shell use.",
                    path=file.path,
                    line=line,
                    evidence="github.event context in run command",
                )
            )
        for match in action.finditer(file.text):
            source = match.group(1)
            reference = match.group(2)
            if source.startswith("docker://"):
                if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", reference):
                    continue
                code = "CI_ACTION_NOT_FULL_SHA"
            elif source.startswith("./") or re.fullmatch(r"[0-9a-fA-F]{40}", reference):
                continue
            else:
                code = "CI_ACTION_FLOATING_REF" if reference.lower() in {"main", "master", "latest"} else "CI_ACTION_NOT_FULL_SHA"
            findings.append(
                _finding(
                    code,
                    "ci",
                    "medium",
                    RULE_HELP[code],
                    "Pin third-party actions to a reviewed commit SHA.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence=f"non-immutable action ref type: {'branch' if reference.lower() in {'main', 'master'} else 'tag'}",
                )
            )
        for match in docker_action_tag.finditer(file.text):
            findings.append(
                _finding(
                    "CI_ACTION_NOT_FULL_SHA",
                    "ci",
                    "medium",
                    RULE_HELP["CI_ACTION_NOT_FULL_SHA"],
                    "Pin container actions to a reviewed sha256 digest.",
                    path=file.path,
                    line=_line_number(file.text, match.start()),
                    evidence="container action uses a mutable tag",
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
    names = {file.path.lower() for file in files}
    for file in files:
        name = PurePosixPath(file.path).name.lower()
        if name in {"requirements.txt", "requirements-dev.txt", "constraints.txt"}:
            findings.extend(_requirement_findings(file))
        elif name == "pyproject.toml" and file.text is not None:
            try:
                document = tomllib.loads(file.text)
            except tomllib.TOMLDecodeError:
                findings.append(_manifest_invalid(file))
                continue
            project = document.get("project", {})
            if not isinstance(project, dict):
                findings.append(_manifest_invalid(file))
                continue
            dependencies = project.get("dependencies", [])
            if not isinstance(dependencies, list):
                findings.append(_manifest_invalid(file))
                continue
            for dependency in dependencies:
                if not isinstance(dependency, str):
                    findings.append(_manifest_invalid(file))
                elif "==" not in dependency and " @ " not in dependency:
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
                findings.append(_manifest_invalid(file))
                continue
            if not isinstance(document, dict):
                findings.append(_manifest_invalid(file))
                continue
            has_dependencies = False
            for section in ("dependencies", "devDependencies"):
                values = document.get(section, {})
                if not isinstance(values, dict):
                    findings.append(_manifest_invalid(file))
                    continue
                has_dependencies = has_dependencies or bool(values)
                for package, version in values.items():
                    if not isinstance(package, str) or not isinstance(version, str):
                        findings.append(_manifest_invalid(file))
                        continue
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
                    elif not _npm_exact_version(version):
                        findings.append(
                            _finding(
                                "DEPENDENCY_UNPINNED",
                                "dependencies",
                                "low",
                                RULE_HELP["DEPENDENCY_UNPINNED"],
                                "Use an exact direct version plus a reviewed lockfile for applications.",
                                path=file.path,
                                evidence=f"{section} entry {str(package)[:80]} uses a version range",
                                classification="inference",
                            )
                        )
            if has_dependencies and not _has_sibling(file.path, names, {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}):
                findings.append(_lock_missing(file, "npm lockfile"))
        elif name == "go.mod" and file.text is not None:
            if not re.search(r"(?m)^\s*module\s+\S+", file.text):
                findings.append(_manifest_invalid(file))
            if re.search(r"(?m)^\s*require\s+(?:\([^)]*\)|\S+)", file.text) and not _has_sibling(file.path, names, {"go.sum"}):
                findings.append(_lock_missing(file, "go.sum"))
            for number, _, version in _go_requirements(file.text):
                if version.endswith(("-master", "-main")):
                    findings.append(_dependency_unpinned(file, number, "Go dependency uses a branch-like version"))
        elif name == "cargo.toml" and file.text is not None:
            try:
                document = tomllib.loads(file.text)
            except tomllib.TOMLDecodeError:
                findings.append(_manifest_invalid(file))
                continue
            dependency_sections = [key for key in document if key.endswith("dependencies")]
            for section in dependency_sections:
                values = document.get(section, {})
                if not isinstance(values, dict):
                    continue
                for package, declaration in values.items():
                    if declaration == "*" or (isinstance(declaration, dict) and "git" in declaration and "rev" not in declaration):
                        findings.append(_dependency_unpinned(file, None, f"Rust dependency {str(package)[:80]} is mutable"))
            if dependency_sections and not _has_sibling(file.path, names, {"cargo.lock"}):
                findings.append(_lock_missing(file, "Cargo.lock (applications should commit it)"))
        elif name == "dockerfile" or name.startswith("dockerfile."):
            if file.text is None:
                continue
            for number, raw in enumerate(file.text.splitlines(), start=1):
                match = re.match(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", raw)
                if match and "@sha256:" not in match.group(1) and not match.group(1).startswith("scratch"):
                    findings.append(
                        _finding(
                            "DOCKER_BASE_UNPINNED",
                            "dependencies",
                            "medium",
                            RULE_HELP["DOCKER_BASE_UNPINNED"],
                            "Pin the reviewed base image to a sha256 digest and automate digest refreshes.",
                            path=file.path,
                            line=number,
                            evidence="base image uses a tag instead of a digest",
                        )
                    )
    return findings


def _has_sibling(path: str, inventory: set[str], candidates: set[str]) -> bool:
    parent = PurePosixPath(path).parent
    return any((parent / candidate).as_posix().lower() in inventory for candidate in candidates)


def _npm_exact_version(value: str) -> bool:
    return bool(re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value))


def _untrusted_shell_interpolation_lines(text: str) -> list[int]:
    lines = text.splitlines()
    findings: list[int] = []
    index = 0
    while index < len(lines):
        raw = lines[index]
        match = re.match(r"^(\s*)(?:-\s*)?run:\s*(.*)$", raw)
        if not match:
            index += 1
            continue
        base_indent = len(match.group(1))
        body = match.group(2)
        if re.search(r"\$\{\{\s*github\.event\.", body):
            findings.append(index + 1)
        if body in {"", "|", ">", "|-", ">-", "|+", ">+"}:
            cursor = index + 1
            while cursor < len(lines):
                candidate = lines[cursor]
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= base_indent:
                    break
                if re.search(r"\$\{\{\s*github\.event\.", candidate):
                    findings.append(cursor + 1)
                cursor += 1
            index = cursor
        else:
            index += 1
    return findings


def _go_requirements(text: str) -> Iterable[tuple[int, str, str]]:
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        elif not in_block:
            continue
        match = re.match(r"([\w./-]+)\s+(v[^\s]+)", line)
        if match:
            yield number, match.group(1), match.group(2)


def _manifest_invalid(file: SourceFile) -> Finding:
    return _finding(
        "DEPENDENCY_MANIFEST_INVALID",
        "dependencies",
        "medium",
        RULE_HELP["DEPENDENCY_MANIFEST_INVALID"],
        "Repair the manifest syntax so dependency policy can be evaluated.",
        path=file.path,
        evidence="manifest parse failed; content omitted",
        classification="blockage",
    )


def _lock_missing(file: SourceFile, expected: str) -> Finding:
    return _finding(
        "DEPENDENCY_LOCK_MISSING",
        "dependencies",
        "low",
        RULE_HELP["DEPENDENCY_LOCK_MISSING"],
        f"Generate and review {expected} for reproducible resolution.",
        path=file.path,
        evidence=f"missing {expected}",
        classification="inference",
    )


def _dependency_unpinned(file: SourceFile, line: int | None, evidence: str) -> Finding:
    return _finding(
        "DEPENDENCY_UNPINNED",
        "dependencies",
        "medium",
        RULE_HELP["DEPENDENCY_UNPINNED"],
        "Replace mutable dependency references with reviewed immutable versions.",
        path=file.path,
        line=line,
        evidence=evidence,
    )


SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("SECRET_PRIVATE_KEY", "critical", re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "SECRET_GITHUB_TOKEN",
        "critical",
        re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
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
        entropy_pattern = re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_+/=.\-]{24,160})['\"]"
        )
        existing_lines = {finding.line for finding in findings if finding.path == file.path}
        for match in entropy_pattern.finditer(file.text):
            value = match.group(1)
            entropy = _shannon_entropy(value)
            line = _line_number(file.text, match.start())
            if entropy >= 4.0 and line not in existing_lines:
                findings.append(
                    _finding(
                        "SECRET_HIGH_ENTROPY",
                        "secrets",
                        "high",
                        RULE_HELP["SECRET_HIGH_ENTROPY"],
                        "Validate and rotate the value, then load it from a secret store.",
                        path=file.path,
                        line=line,
                        evidence=f"redacted high-entropy assignment ({len(value)} characters; entropy {entropy:.2f})",
                        classification="inference",
                    )
                )
    return findings


def _shannon_entropy(value: str) -> float:
    frequencies = {character: value.count(character) / len(value) for character in sorted(set(value))}
    return -sum(frequencies[character] * math.log2(frequencies[character]) for character in sorted(frequencies))


def audit_todos(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(?i)\b(TODO|FIXME)\b")
    for file in files:
        if file.text is None:
            continue
        matches: list[tuple[str, int]] = []
        if file.path.endswith(".py"):
            try:
                tokens = tokenize.generate_tokens(io.StringIO(file.text).readline)
                for token in tokens:
                    if token.type != tokenize.COMMENT:
                        continue
                    matches.extend((match.group(1).upper(), token.start[0]) for match in pattern.finditer(token.string))
            except (IndentationError, tokenize.TokenError):
                for number, line in enumerate(file.text.splitlines(), start=1):
                    comment = line.partition("#")[2]
                    matches.extend((match.group(1).upper(), number) for match in pattern.finditer(comment))
        else:
            matches = [
                (match.group(1).upper(), _line_number(file.text, match.start()))
                for match in pattern.finditer(file.text)
            ]
        for index, (marker, line) in enumerate(matches):
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
                    line=line,
                    evidence=f"marker: {marker}",
                )
            )
    return findings


def audit_debt(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
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
        try:
            tree = ast.parse(file.text)
            bare_lines = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler) and node.type is None]
            dynamic_calls = [
                (node.func.id, node.lineno)
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"eval", "exec"}
            ]
        except SyntaxError:
            bare_pattern = re.compile(r"(?m)^\s*except\s*:\s*(?:#.*)?$")
            dynamic_pattern = re.compile(r"\b(eval|exec)\s*\(")
            bare_lines = [_line_number(file.text, match.start()) for match in bare_pattern.finditer(file.text)]
            dynamic_calls = [
                (match.group(1), _line_number(file.text, match.start()))
                for match in dynamic_pattern.finditer(file.text)
            ]
        for line in bare_lines:
            findings.append(
                _finding(
                    "DEBT_BARE_EXCEPT",
                    "debt",
                    "medium",
                    RULE_HELP["DEBT_BARE_EXCEPT"],
                    "Catch the narrow expected exception and preserve unexpected failures.",
                    path=file.path,
                    line=line,
                    evidence="bare except clause",
                )
            )
        for call, line in dynamic_calls:
            findings.append(
                _finding(
                    "DEBT_DYNAMIC_EXEC",
                    "debt",
                    "high",
                    RULE_HELP["DEBT_DYNAMIC_EXEC"],
                    "Replace dynamic execution with a bounded parser or explicit dispatch table.",
                    path=file.path,
                    line=line,
                    evidence=f"dynamic call: {call}",
                )
            )
    return findings


def audit_repository(files: tuple[SourceFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        path = PurePosixPath(file.path)
        lower_parts = {part.lower() for part in path.parts}
        name = path.name.lower()
        if file.size > 512 * 1024:
            findings.append(
                _finding(
                    "REPOSITORY_LARGE_FILE",
                    "repository",
                    "medium",
                    RULE_HELP["REPOSITORY_LARGE_FILE"],
                    "Store large artifacts in a release/object store or document why source control is required.",
                    path=file.path,
                    evidence=f"{file.size} bytes exceeds 524288-byte review policy",
                )
            )
        if lower_parts.intersection({"vendor", "third_party", "third-party"}):
            findings.append(
                _finding(
                    "REPOSITORY_VENDOR_TRACKED",
                    "repository",
                    "low",
                    RULE_HELP["REPOSITORY_VENDOR_TRACKED"],
                    "Document provenance, license review, update cadence, and integrity checks for vendored code.",
                    path=file.path,
                    evidence="file under a conventional vendor directory",
                    classification="inference",
                )
            )
        generated_marker = file.text is not None and re.search(r"(?i)(?:@generated|do not edit|automatically generated)", file.text[:2048])
        if name.endswith((".min.js", ".min.css", ".map")) or generated_marker:
            findings.append(
                _finding(
                    "REPOSITORY_GENERATED_TRACKED",
                    "repository",
                    "low",
                    RULE_HELP["REPOSITORY_GENERATED_TRACKED"],
                    "Prefer reproducible generation in CI or document the generator and review policy.",
                    path=file.path,
                    evidence="generated filename or bounded header marker",
                    classification="inference",
                )
            )
    return findings


def _root_names(files: tuple[SourceFile, ...]) -> set[str]:
    return {PurePosixPath(file.path).name.lower() for file in files if "/" not in file.path}


def audit_ownership(files: tuple[SourceFile, ...]) -> list[Finding]:
    paths = {file.path.lower() for file in files}
    names = _root_names(files)
    findings: list[Finding] = []
    if not paths.intersection({"codeowners", ".github/codeowners", "docs/codeowners"}):
        findings.append(
            _finding(
                "OWNERSHIP_CODEOWNERS_MISSING",
                "ownership",
                "low",
                RULE_HELP["OWNERSHIP_CODEOWNERS_MISSING"],
                "Add CODEOWNERS with explicit ownership for security-sensitive and release paths.",
                evidence="CODEOWNERS path inventory",
            )
        )
    if not names.intersection({"maintainers", "maintainers.md", "governance.md", "owners.md"}):
        findings.append(
            _finding(
                "OWNERSHIP_MAINTAINERS_MISSING",
                "ownership",
                "low",
                RULE_HELP["OWNERSHIP_MAINTAINERS_MISSING"],
                "Document current maintainers, decision authority, and succession expectations.",
                evidence="root governance file inventory",
            )
        )
    return findings


def audit_documentation(files: tuple[SourceFile, ...]) -> list[Finding]:
    paths = {file.path.lower() for file in files}
    names = _root_names(files)
    findings: list[Finding] = []
    if not any("architecture" in path or path.endswith("adr.md") for path in paths):
        findings.append(
            _finding(
                "DOCUMENTATION_ARCHITECTURE_MISSING",
                "documentation",
                "low",
                RULE_HELP["DOCUMENTATION_ARCHITECTURE_MISSING"],
                "Add an architecture overview with boundaries, data flow, and trust assumptions.",
                evidence="documentation path inventory",
            )
        )
    operations_names = {"runbook.md", "operations.md", "deployment.md", "deploy.md"}
    if not names.intersection(operations_names) and not any(PurePosixPath(path).name in operations_names for path in paths):
        findings.append(
            _finding(
                "DOCUMENTATION_OPERATIONS_MISSING",
                "documentation",
                "low",
                RULE_HELP["DOCUMENTATION_OPERATIONS_MISSING"],
                "Document build, release, rollback, and failure-recovery procedures.",
                evidence="runbook and operations path inventory",
                classification="inference",
            )
        )
    return findings


def audit_release(files: tuple[SourceFile, ...]) -> list[Finding]:
    names = _root_names(files)
    findings: list[Finding] = []
    if not names.intersection({"changelog", "changelog.md", "history.md", "releases.md", "news.md"}):
        findings.append(
            _finding(
                "RELEASE_CHANGELOG_MISSING",
                "release",
                "low",
                RULE_HELP["RELEASE_CHANGELOG_MISSING"],
                "Add a changelog with dated, user-visible release notes.",
                evidence="root release-notes inventory",
            )
        )
    versions: dict[str, str] = {}
    for file in files:
        name = PurePosixPath(file.path).name.lower()
        if file.text is None:
            continue
        if name == "pyproject.toml":
            try:
                project = tomllib.loads(file.text).get("project", {})
                value = project.get("version") if isinstance(project, dict) else None
            except tomllib.TOMLDecodeError:
                value = None
            if isinstance(value, str):
                versions[file.path] = value
        elif name == "package.json":
            try:
                value = json.loads(file.text).get("version")
            except (json.JSONDecodeError, AttributeError):
                value = None
            if isinstance(value, str):
                versions[file.path] = value
        elif name == "cargo.toml":
            try:
                package = tomllib.loads(file.text).get("package", {})
                value = package.get("version") if isinstance(package, dict) else None
            except tomllib.TOMLDecodeError:
                value = None
            if isinstance(value, str):
                versions[file.path] = value
        elif name == "__init__.py":
            match = re.search(r"(?m)^__version__\s*=\s*['\"]([^'\"]+)['\"]", file.text)
            if match:
                versions[file.path] = match.group(1)
    if len(set(versions.values())) > 1:
        findings.append(
            _finding(
                "RELEASE_VERSION_MISMATCH",
                "release",
                "medium",
                RULE_HELP["RELEASE_VERSION_MISMATCH"],
                "Use one release version source or validate all declarations in CI.",
                evidence=f"{len(versions)} declarations contain {len(set(versions.values()))} distinct versions",
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
    "repository": audit_repository,
    "ownership": audit_ownership,
    "documentation": audit_documentation,
    "release": audit_release,
}


def build_default_registry():
    """Build a fresh registry so callers can add trusted plugins without global mutation."""

    from .registry import RulePlugin, RuleRegistry

    descriptions = {
        "structure": "Required repository entry-point files",
        "tests": "Recognized executable test inventory",
        "ci": "GitHub Actions triggers, permissions, interpolation, and immutable action refs",
        "dependencies": "Python, npm, Go, Rust, and Docker dependency policy",
        "secrets": "Redacted credential shapes and high-entropy assignments",
        "todos": "Bounded unfinished-work markers",
        "debt": "Review-sensitive Python source patterns",
        "repository": "Generated, vendored, and oversized tracked-file policy",
        "ownership": "Code ownership and maintainership governance",
        "documentation": "Architecture and operational documentation",
        "release": "Release notes and cross-manifest version consistency",
    }
    return RuleRegistry(
        RulePlugin(f"builtin.{category}", category, descriptions[category], auditor)
        for category, auditor in AUDITORS.items()
    )
