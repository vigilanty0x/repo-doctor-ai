"""Offline, bounded CycloneDX-compatible dependency inventory."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import time
import tomllib
from typing import Any, Iterable
from urllib.parse import quote
import uuid

from .config import Config
from .io_utils import BoundedReadError, ConfinedReader
from .sanitization import safe_output_text


class SbomError(ValueError):
    """The requested SBOM inventory could not be completed safely."""


MAX_COMPONENTS = 50_000


def build_sbom(root: str | Path, config: Config | None = None) -> dict[str, Any]:
    policy = config or Config()
    root_path = Path(root)
    if not root_path.is_dir():
        raise SbomError("SBOM root is not a directory")
    resolved_root = root_path.resolve()
    manifests: list[tuple[str, str]] = []
    files_seen = 0
    bytes_read = 0
    deadline = time.monotonic() + policy.timeout_seconds
    reader = ConfinedReader(resolved_root)
    try:
        reader.__enter__()
    except BoundedReadError as exc:
        raise SbomError(f"cannot open SBOM root safely: {exc}") from exc
    try:
        for current, directories, names in os.walk(resolved_root, topdown=True, followlinks=False):
            if time.monotonic() >= deadline:
                raise SbomError("SBOM inventory reached timeout_seconds")
            relative_dir = Path(current).relative_to(resolved_root)
            directories[:] = sorted(
                directory
                for directory in directories
                if not _excluded((relative_dir / directory).as_posix(), directory, policy)
                and not (Path(current) / directory).is_symlink()
            )
            for name in sorted(names):
                if time.monotonic() >= deadline:
                    raise SbomError("SBOM inventory reached timeout_seconds")
                relative = (relative_dir / name).as_posix().removeprefix("./")
                if _excluded(relative, name, policy):
                    continue
                files_seen += 1
                if files_seen > policy.max_files:
                    raise SbomError("SBOM inventory reached max_files")
                if not _is_manifest(name):
                    continue
                candidate = Path(current) / name
                if candidate.is_symlink():
                    continue
                try:
                    encoded, _ = reader.read_bounded_bytes(
                        relative,
                        policy.max_file_bytes,
                        label=f"manifest {relative}",
                        remaining_bytes=policy.max_total_bytes - bytes_read,
                    )
                    bytes_read += len(encoded)
                    manifests.append((relative, encoded.decode("utf-8")))
                except (UnicodeError, BoundedReadError) as exc:
                    if isinstance(exc, BoundedReadError) and exc.reason == "total_limit":
                        raise SbomError("SBOM inventory reached max_total_bytes") from exc
                    raise SbomError(f"cannot read manifest {relative}: {type(exc).__name__}") from exc
    finally:
        reader.__exit__(None, None, None)

    components: dict[str, dict[str, Any]] = {}
    for path, text in manifests:
        if time.monotonic() >= deadline:
            raise SbomError("SBOM inventory reached timeout_seconds")
        for component in _components(path, text):
            if time.monotonic() >= deadline:
                raise SbomError("SBOM inventory reached timeout_seconds")
            if component["bom-ref"] not in components and len(components) >= MAX_COMPONENTS:
                raise SbomError(f"SBOM inventory exceeds {MAX_COMPONENTS} unique components")
            components.setdefault(component["bom-ref"], component)
    ordered = [components[key] for key in sorted(components)]
    identity = json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    root_name = safe_output_text(resolved_root.name or "repository")
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"repo-doctor:{root_name}:{hashlib.sha256(identity.encode()).hexdigest()}",
    )
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "repo-doctor-ai"}]},
            "component": {"type": "application", "name": root_name},
            "properties": [
                {"name": "repo-doctor:mode", "value": "offline-static-manifest-inventory"},
                {"name": "repo-doctor:manifests", "value": str(len(manifests))},
            ],
        },
        "components": ordered,
    }


def _is_manifest(name: str) -> bool:
    lowered = name.lower()
    return lowered in {
        "requirements.txt",
        "requirements-dev.txt",
        "constraints.txt",
        "pyproject.toml",
        "package.json",
        "go.mod",
        "cargo.toml",
        "dockerfile",
    } or lowered.startswith("dockerfile.")


def _excluded(relative: str, name: str, config: Config) -> bool:
    parts = set(PurePosixPath(relative).parts)
    for item in config.exclude:
        normalized = item.replace("\\", "/").strip("/")
        if "/" in normalized:
            if relative == normalized or relative.startswith(normalized + "/"):
                return True
        elif name == normalized or normalized in parts:
            return True
    return False


def _components(path: str, text: str) -> Iterable[dict[str, Any]]:
    name = PurePosixPath(path).name.lower()
    if name.startswith("requirements") or name == "constraints.txt":
        for raw in text.splitlines():
            requirement = raw.strip()
            if not requirement or requirement.startswith(("#", "-")):
                continue
            yield _python_component(requirement, path)
    elif name == "pyproject.toml":
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise SbomError(f"invalid manifest {path}: TOML syntax") from exc
        project = document.get("project", {})
        if not isinstance(project, dict):
            raise SbomError(f"invalid manifest {path}: project must be a table")
        dependencies = project.get("dependencies", [])
        if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
            raise SbomError(f"invalid manifest {path}: dependencies must be strings")
        for requirement in dependencies:
            yield _python_component(requirement, path)
    elif name == "package.json":
        try:
            document = json.loads(text, object_pairs_hook=_unique_manifest_object)
        except (json.JSONDecodeError, SbomError) as exc:
            raise SbomError(f"invalid manifest {path}: JSON syntax or duplicate key") from exc
        if not isinstance(document, dict):
            raise SbomError(f"invalid manifest {path}: root must be an object")
        for section, scope in (("dependencies", "required"), ("devDependencies", "optional")):
            values = document.get(section, {})
            if not isinstance(values, dict):
                raise SbomError(f"invalid manifest {path}: {section} must be an object")
            for package, version in values.items():
                if not isinstance(package, str) or not isinstance(version, str):
                    raise SbomError(f"invalid manifest {path}: dependency entries must be strings")
                yield _component("library", "npm", package, version, path, scope)
    elif name == "go.mod":
        in_block = False
        for raw in text.splitlines():
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
            match = re.match(r"([\w./-]+)\s+(v[^\s]+)(?:\s+//.*)?$", line)
            if match:
                yield _component("library", "golang", match.group(1), match.group(2), path)
    elif name == "cargo.toml":
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise SbomError(f"invalid manifest {path}: TOML syntax") from exc
        for section, values in document.items() if isinstance(document, dict) else ():
            if not section.endswith("dependencies") or not isinstance(values, dict):
                continue
            for package, declaration in values.items():
                if isinstance(declaration, str):
                    version = declaration
                elif isinstance(declaration, dict):
                    version = str(declaration.get("version") or declaration.get("rev") or "unknown")
                else:
                    continue
                yield _component("library", "cargo", str(package), version, path)
    elif name == "dockerfile" or name.startswith("dockerfile."):
        for raw in text.splitlines():
            match = re.match(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", raw)
            if match:
                image = match.group(1)
                image_name, version = _image_version(image)
                yield _component("container", "oci", image_name, version, path)


def _python_component(requirement: str, path: str) -> dict[str, Any]:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", requirement)
    if not match:
        return _component("library", "pypi", requirement[:120], "unknown", path)
    declaration = match.group(2).split(";", 1)[0].strip()
    if declaration.startswith("@"):
        version = "direct-url-redacted"
    else:
        version = declaration[2:] if declaration.startswith("==") else (declaration or "unknown")
    return _component("library", "pypi", match.group(1), version, path)


def _component(
    component_type: str,
    ecosystem: str,
    name: str,
    version: str,
    source: str,
    scope: str = "required",
) -> dict[str, Any]:
    direct_locator = r"(?:[A-Za-z][A-Za-z0-9+.-]*://|^git\+|^git@[^:]+:|^github:|^gitlab:)"
    if re.search(direct_locator, name):
        name = "direct-url-redacted"
    else:
        name = safe_output_text(name)
    if re.search(direct_locator, version):
        version = "direct-url-redacted"
    else:
        version = safe_output_text(version)
    source = safe_output_text(source)
    identity = f"{ecosystem}:{name}@{version}"
    reference = f"pkg:{ecosystem}/{quote(name, safe='/._~-')}@{quote(version, safe='._~+-')}"
    return {
        "type": component_type,
        "bom-ref": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
        "name": name[:256],
        "version": version[:256],
        "scope": scope,
        "purl": reference[:1024],
        "properties": [{"name": "repo-doctor:source-manifest", "value": source}],
    }


def _image_version(image: str) -> tuple[str, str]:
    if "@" in image:
        return tuple(image.split("@", 1))  # type: ignore[return-value]
    final = image.rsplit("/", 1)[-1]
    if ":" in final:
        prefix, version = image.rsplit(":", 1)
        return prefix, version
    return image, "latest"


def _unique_manifest_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SbomError(f"duplicate manifest key: {key}")
        result[key] = value
    return result
