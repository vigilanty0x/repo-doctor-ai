"""Append-only, process-safe, idempotent audit journal."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator
import uuid

from .io_utils import BoundedReadError, read_bounded_bytes
from .sanitization import sanitize_json_value


ZERO_HASH = "0" * 64
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 16 * 1024 * 1024
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class JournalError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JournalError(f"journal value is not strict JSON: {exc}") from exc


def _hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JournalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise JournalError(f"non-finite JSON number is not allowed: {value}")


class AuditJournal:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a+b", closefd=True) as handle:
            if os.name == "nt":  # pragma: no cover - exercised on Windows CI
                import msvcrt

                if handle.seek(0, os.SEEK_END) == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def replay(self) -> tuple[dict[str, Any], ...]:
        with self._lock():
            return self._replay_unlocked(allow_missing=False)

    def _replay_unlocked(self, *, allow_missing: bool) -> tuple[dict[str, Any], ...]:
        if not self.path.exists():
            if allow_missing:
                return ()
            raise JournalError(f"journal does not exist: {self.path}")
        try:
            encoded = read_bounded_bytes(self.path, MAX_JOURNAL_BYTES, label="journal")
            if encoded and not encoded.endswith(b"\n"):
                raise JournalError("journal must end with a newline before replay or append")
            lines = encoded.decode("utf-8").splitlines()
        except (BoundedReadError, UnicodeDecodeError) as exc:
            raise JournalError(f"cannot read journal: {exc}") from exc
        events: list[dict[str, Any]] = []
        previous = ZERO_HASH
        keys: set[str] = set()
        for sequence, line in enumerate(lines, start=1):
            if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
                raise JournalError(f"journal event exceeds {MAX_EVENT_BYTES} bytes at line {sequence}")
            try:
                event = json.loads(
                    line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
                )
            except JournalError:
                raise
            except json.JSONDecodeError as exc:
                raise JournalError(f"invalid journal JSON at line {sequence}: {exc}") from exc
            required = {"event_id", "run_id", "sequence", "timestamp", "report", "previous_hash", "hash"}
            if not isinstance(event, dict) or set(event) != required:
                raise JournalError(f"invalid journal event at line {sequence}")
            if isinstance(event["sequence"], bool) or event["sequence"] != sequence:
                raise JournalError(f"journal sequence mismatch at line {sequence}")
            if event["previous_hash"] != previous:
                raise JournalError(f"journal chain mismatch at line {sequence}")
            if not isinstance(event["run_id"], str) or not RUN_ID_RE.fullmatch(event["run_id"]) or event["run_id"] in keys:
                raise JournalError(f"duplicate or invalid run_id at line {sequence}")
            if not isinstance(event["event_id"], str):
                raise JournalError(f"invalid event_id at line {sequence}")
            try:
                uuid.UUID(event["event_id"])
                datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            except (ValueError, TypeError) as exc:
                raise JournalError(f"invalid event identity or timestamp at line {sequence}") from exc
            if not isinstance(event["report"], dict):
                raise JournalError(f"invalid report at line {sequence}")
            try:
                safe_report = sanitize_json_value(event["report"])
            except ValueError as exc:
                raise JournalError(f"unsafe report at line {sequence}: {exc}") from exc
            if safe_report != event["report"]:
                raise JournalError(f"unsafe unsanitized report at line {sequence}")
            unsigned = dict(event)
            claimed = unsigned.pop("hash")
            if not isinstance(claimed, str) or not SHA_RE.fullmatch(claimed) or claimed != _hash(unsigned):
                raise JournalError(f"journal event hash mismatch at line {sequence}")
            keys.add(event["run_id"])
            previous = claimed
            events.append(event)
        return tuple(events)

    def append(self, run_id: str, report: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise JournalError("run_id must be a safe 1 to 256 character identifier")
        if not isinstance(report, dict):
            raise JournalError("report must be a JSON object")
        try:
            safe_report = sanitize_json_value(report)
        except ValueError as exc:
            raise JournalError(f"journal report cannot be sanitized safely: {exc}") from exc
        if not isinstance(safe_report, dict):  # defensive: sanitize_json_value preserves mappings
            raise JournalError("report must be a JSON object")
        report_bytes = _canonical(safe_report)
        with self._lock():
            events = self._replay_unlocked(allow_missing=True)
            for event in events:
                if event["run_id"] == run_id:
                    if _canonical(event["report"]) == report_bytes:
                        return event
                    raise JournalError(f"idempotency conflict for run_id: {run_id}")
            unsigned = {
                "event_id": str(uuid.uuid4()),
                "run_id": run_id,
                "sequence": len(events) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "report": safe_report,
                "previous_hash": events[-1]["hash"] if events else ZERO_HASH,
            }
            event = {**unsigned, "hash": _hash(unsigned)}
            encoded = _canonical(event) + b"\n"
            if len(encoded) > MAX_EVENT_BYTES:
                raise JournalError(f"journal event exceeds {MAX_EVENT_BYTES} bytes")
            flags = (
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor: int | None = None
            try:
                descriptor = os.open(self.path, flags, 0o600)
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise JournalError("journal must be a regular file")
                if metadata.st_size + len(encoded) > MAX_JOURNAL_BYTES:
                    raise JournalError(f"journal would exceed {MAX_JOURNAL_BYTES} bytes")
                with os.fdopen(descriptor, "ab", closefd=True) as handle:
                    descriptor = None
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
            except JournalError:
                raise
            except OSError as exc:
                raise JournalError(f"cannot append journal: {exc}") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            return event
