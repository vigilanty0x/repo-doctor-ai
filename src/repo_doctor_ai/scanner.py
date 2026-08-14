"""Bounded local repository scanner."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import time
from typing import Callable

from .config import Config
from .models import Finding, Report, SEVERITY_ORDER
from .rules import AUDITORS, SourceFile


class Scanner:
    def __init__(self, config: Config | None = None, *, clock: Callable[[], float] = time.monotonic):
        self.config = config or Config()
        self.clock = clock

    def scan(self, root: str | Path) -> Report:
        root_path = Path(root)
        if not root_path.is_dir():
            return Report(
                root=root_path.name or ".",
                state="REJECTED",
                status="blocked",
                result="FAIL",
                reason_code="ROOT_INVALID",
                findings=(),
                metrics=self._metrics(),
                errors=("evaluation root is not a directory",),
            )

        resolved_root = root_path.resolve()
        deadline = self.clock() + self.config.timeout_seconds
        files: list[SourceFile] = []
        operational: list[Finding] = []
        errors: list[str] = []
        metrics = self._metrics()
        stop_reason: str | None = None

        def on_error(exc: OSError) -> None:
            nonlocal stop_reason
            errors.append(f"walk error: {type(exc).__name__}")
            metrics["errors"] += 1
            if metrics["errors"] >= self.config.error_threshold:
                stop_reason = "CIRCUIT_OPEN"

        for current, directories, names in os.walk(resolved_root, topdown=True, onerror=on_error, followlinks=False):
            relative_dir = Path(current).relative_to(resolved_root)
            directories[:] = sorted(
                directory
                for directory in directories
                if not self._excluded((relative_dir / directory).as_posix(), directory)
                and not (Path(current) / directory).is_symlink()
            )
            for name in sorted(names):
                if stop_reason:
                    break
                if self.clock() >= deadline:
                    stop_reason = "TIMEOUT"
                    break
                relative = (relative_dir / name).as_posix()
                if relative.startswith("./"):
                    relative = relative[2:]
                if self._excluded(relative, name):
                    metrics["excluded_files"] += 1
                    continue
                if metrics["files_seen"] >= self.config.max_files:
                    stop_reason = "FILE_LIMIT"
                    break
                metrics["files_seen"] += 1
                candidate = Path(current) / name
                try:
                    resolved = candidate.resolve()
                    if resolved != resolved_root and resolved_root not in resolved.parents:
                        operational.append(
                            Finding(
                                "SCAN_PATH_ESCAPE",
                                "scanner",
                                "high",
                                "blockage",
                                "A resolved file path escapes the audit root.",
                                "Remove or exclude the escaping symlink.",
                                relative,
                                None,
                                "resolved path outside root",
                            )
                        )
                        metrics["errors"] += 1
                        continue
                    size = candidate.stat().st_size
                    if size > self.config.max_file_bytes:
                        metrics["skipped_large_files"] += 1
                        operational.append(
                            Finding(
                                "SCAN_FILE_SKIPPED_LARGE",
                                "scanner",
                                "low",
                                "inference",
                                "A file exceeded the configured content limit and was not inspected.",
                                "Audit the file separately or raise the reviewed size limit.",
                                relative,
                                None,
                                f"{size} bytes",
                            )
                        )
                        files.append(SourceFile(relative, size, None))
                        continue
                    content = candidate.read_bytes()
                    metrics["bytes_read"] += len(content)
                    if b"\x00" in content[:8192]:
                        metrics["binary_files"] += 1
                        files.append(SourceFile(relative, size, None))
                        continue
                    text = content.decode("utf-8", "replace")
                    files.append(SourceFile(relative, size, text))
                    metrics["files_scanned"] += 1
                except OSError as exc:
                    errors.append(f"{relative}: {type(exc).__name__}")
                    metrics["errors"] += 1
                    operational.append(
                        Finding(
                            "SCAN_FILE_UNREADABLE",
                            "scanner",
                            "medium",
                            "blockage",
                            "A repository file could not be read.",
                            "Check filesystem permissions and retry the audit.",
                            relative,
                            None,
                            type(exc).__name__,
                        )
                    )
                    if metrics["errors"] >= self.config.error_threshold:
                        stop_reason = "CIRCUIT_OPEN"
            if stop_reason:
                break

        findings = list(operational)
        for category in self.config.enabled_categories:
            if self.clock() >= deadline:
                stop_reason = stop_reason or "TIMEOUT"
                break
            findings.extend(AUDITORS[category](tuple(files)))

        findings.sort(
            key=lambda finding: (
                -SEVERITY_ORDER[finding.severity],
                finding.category,
                finding.path or "",
                finding.line or 0,
                finding.code,
                finding.fingerprint,
            )
        )
        metrics["findings"] = len(findings)

        if stop_reason == "CIRCUIT_OPEN":
            state, status, reason = "REJECTED", "blocked", "CIRCUIT_OPEN"
        elif stop_reason in {"TIMEOUT", "FILE_LIMIT"}:
            state, status, reason = "WAITING", "blocked", stop_reason
        elif errors:
            state, status, reason = "DEGRADED", "blocked", "AUDIT_DEGRADED"
        else:
            state, status, reason = "DONE", "verified", "AUDIT_COMPLETE"

        if any(finding.severity in {"critical", "high"} for finding in findings):
            result = "FAIL"
        elif findings:
            result = "WARN"
        else:
            result = "PASS"
        return Report(
            root=resolved_root.name or ".",
            state=state,
            status=status,
            result=result,
            reason_code=reason,
            findings=tuple(findings),
            metrics=metrics,
            errors=tuple(errors),
        )

    def _excluded(self, relative: str, name: str) -> bool:
        path = PurePosixPath(relative)
        parts = set(path.parts)
        for excluded in self.config.exclude:
            normalized = excluded.replace("\\", "/").strip("/")
            if "/" in normalized:
                if relative == normalized or relative.startswith(normalized + "/"):
                    return True
            elif name == normalized or normalized in parts:
                return True
        return False

    @staticmethod
    def _metrics() -> dict[str, int]:
        return {
            "files_seen": 0,
            "files_scanned": 0,
            "bytes_read": 0,
            "binary_files": 0,
            "skipped_large_files": 0,
            "excluded_files": 0,
            "errors": 0,
            "findings": 0,
        }

