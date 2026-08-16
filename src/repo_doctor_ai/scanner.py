"""Bounded local repository scanner."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import signal
import threading
import time
from typing import Callable, Iterator

from .baseline import Baseline
from .config import Config
from .io_utils import BoundedReadError, ConfinedReader
from .models import Finding, Report, SEVERITY_ORDER
from .registry import RegistryDeadlineExceeded, RuleRegistry
from .rules import SourceFile, build_default_registry


class Scanner:
    def __init__(
        self,
        config: Config | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        registry: RuleRegistry | None = None,
    ):
        self.config = config or Config()
        self.clock = clock
        self.registry = registry or build_default_registry()

    def scan(self, root: str | Path, *, baseline: Baseline | None = None) -> Report:
        root_path = Path(root)
        if not root_path.is_dir():
            invalid_metrics = self._metrics()
            invalid_metrics["errors"] = 1
            return Report(
                root=root_path.name or ".",
                state="REJECTED",
                status="blocked",
                result="PASS",
                reason_code="ROOT_INVALID",
                findings=(),
                metrics=invalid_metrics,
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

        reader = ConfinedReader(resolved_root)
        try:
            reader.__enter__()
        except BoundedReadError as exc:
            metrics["errors"] = 1
            return Report(
                root=resolved_root.name or ".",
                state="REJECTED",
                status="blocked",
                result="PASS",
                reason_code="ROOT_INVALID",
                findings=(),
                metrics=metrics,
                errors=(str(exc),),
            )
        try:
            for current, directories, names in os.walk(
                resolved_root, topdown=True, onerror=on_error, followlinks=False
            ):
                if self.clock() >= deadline:
                    stop_reason = "TIMEOUT"
                    break
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
                        if candidate.is_symlink():
                            metrics["symlink_files"] += 1
                            operational.append(
                                Finding(
                                    "SCAN_SYMLINK_SKIPPED",
                                    "scanner",
                                    "low",
                                    "inference",
                                    "A file symlink was not followed during the audit.",
                                    "Audit the resolved target separately if it is part of the review boundary.",
                                    relative,
                                    None,
                                    "file symlink skipped",
                                )
                            )
                            continue
                        content, size = reader.read_bounded_bytes(
                            relative,
                            self.config.max_file_bytes,
                            label=relative,
                            remaining_bytes=self.config.max_total_bytes - metrics["bytes_read"],
                        )
                        metrics["bytes_read"] += len(content)
                        if b"\x00" in content[:8192]:
                            metrics["binary_files"] += 1
                            files.append(SourceFile(relative, size, None))
                            continue
                        text = content.decode("utf-8", "replace")
                        files.append(SourceFile(relative, size, text))
                        metrics["files_scanned"] += 1
                    except BoundedReadError as exc:
                        if exc.reason == "file_limit":
                            size = exc.actual_size or self.config.max_file_bytes + 1
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
                        if exc.reason == "total_limit":
                            stop_reason = "BYTE_LIMIT"
                            break
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
        finally:
            reader.__exit__(None, None, None)

        findings = list(operational)
        executed_plugins: tuple[str, ...] = ()
        if self.clock() >= deadline:
            stop_reason = stop_reason or "TIMEOUT"
        elif len(findings) >= self.config.max_findings:
            findings = findings[: self.config.max_findings]
            stop_reason = stop_reason or "FINDING_LIMIT"
        else:
            available = self.config.max_findings - len(findings)
            try:
                with _deadline_guard(deadline, self.clock):
                    rule_findings, executed_plugins, truncated = self.registry.run(
                        tuple(files),
                        self.config.enabled_categories,
                        max_findings=available,
                        deadline=deadline,
                        clock=self.clock,
                    )
                findings.extend(rule_findings)
                if self.clock() >= deadline:
                    stop_reason = stop_reason or "TIMEOUT"
                elif truncated:
                    stop_reason = stop_reason or "FINDING_LIMIT"
            except RegistryDeadlineExceeded as exc:
                findings.extend(exc.findings)
                executed_plugins = exc.executed
                stop_reason = stop_reason or "TIMEOUT"

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
        metrics["rules_executed"] = len(executed_plugins)
        suppressed = ()
        if baseline is not None:
            active, suppressed, expired = baseline.apply(findings)
            findings = list(active)
            metrics["suppressed_findings"] = len(suppressed)
            metrics["expired_suppressions"] = len(expired)
        metrics["findings"] = len(findings)

        if stop_reason == "CIRCUIT_OPEN":
            state, status, reason = "REJECTED", "blocked", "CIRCUIT_OPEN"
        elif stop_reason in {"TIMEOUT", "FILE_LIMIT", "BYTE_LIMIT", "FINDING_LIMIT"}:
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
            suppressed_findings=suppressed,
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
            "symlink_files": 0,
            "skipped_large_files": 0,
            "excluded_files": 0,
            "errors": 0,
            "findings": 0,
            "rules_executed": 0,
            "suppressed_findings": 0,
            "expired_suppressions": 0,
        }


@contextmanager
def _deadline_guard(deadline: float, clock: Callable[[], float]) -> Iterator[None]:
    """Preempt a blocking rule on POSIX main threads; retain cooperative checks elsewhere."""

    remaining = deadline - clock()
    if remaining <= 0:
        raise RegistryDeadlineExceeded([], ())
    supported = (
        hasattr(signal, "setitimer")
        and hasattr(signal, "ITIMER_REAL")
        and threading.current_thread() is threading.main_thread()
    )
    if not supported:
        yield
        return
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer[0] > 0:
        # Never steal a caller-owned process timer. DeadlineFiles still enforces
        # the budget cooperatively at every inventory and finding boundary.
        yield
        return
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expire(_signum: int, _frame: object) -> None:
        raise RegistryDeadlineExceeded([], ())

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
