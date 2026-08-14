"""Append-only, idempotent audit journal."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any
import uuid

ZERO_HASH = "0" * 64
MAX_JOURNAL_BYTES = 64 * 1024 * 1024


class JournalError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class AuditJournal:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def replay(self) -> tuple[dict[str, Any], ...]:
        if not self.path.exists():
            return ()
        try:
            if self.path.stat().st_size > MAX_JOURNAL_BYTES:
                raise JournalError(f"journal exceeds {MAX_JOURNAL_BYTES} bytes")
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except JournalError:
            raise
        except (OSError, UnicodeError) as exc:
            raise JournalError(f"cannot read journal: {exc}") from exc
        events: list[dict[str, Any]] = []
        previous = ZERO_HASH
        keys: set[str] = set()
        for sequence, line in enumerate(lines, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise JournalError(f"invalid journal JSON at line {sequence}: {exc}") from exc
            required = {"event_id", "run_id", "sequence", "timestamp", "report", "previous_hash", "hash"}
            if not isinstance(event, dict) or set(event) != required:
                raise JournalError(f"invalid journal event at line {sequence}")
            if event["sequence"] != sequence or event["previous_hash"] != previous:
                raise JournalError(f"journal chain mismatch at line {sequence}")
            if not isinstance(event["run_id"], str) or not event["run_id"] or event["run_id"] in keys:
                raise JournalError(f"duplicate or invalid run_id at line {sequence}")
            unsigned = dict(event)
            claimed = unsigned.pop("hash")
            if claimed != _hash(unsigned):
                raise JournalError(f"journal event hash mismatch at line {sequence}")
            keys.add(event["run_id"])
            previous = claimed
            events.append(event)
        return tuple(events)

    def append(self, run_id: str, report: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(run_id, str) or not run_id or len(run_id) > 256:
            raise JournalError("run_id must be 1 to 256 characters")
        events = self.replay()
        for event in events:
            if event["run_id"] == run_id:
                if event["report"] == report:
                    return event
                raise JournalError(f"idempotency conflict for run_id: {run_id}")
        unsigned = {
            "event_id": str(uuid.uuid4()),
            "run_id": run_id,
            "sequence": len(events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "report": report,
            "previous_hash": events[-1]["hash"] if events else ZERO_HASH,
        }
        event = {**unsigned, "hash": _hash(unsigned)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("ab") as handle:
                handle.write(_canonical(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise JournalError(f"cannot append journal: {exc}") from exc
        return event

