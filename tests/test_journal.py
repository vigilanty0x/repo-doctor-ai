from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from unittest.mock import patch

from repo_doctor_ai.journal import AuditJournal, JournalError


def _append_concurrently(arguments: tuple[str, int]) -> int:
    path, index = arguments
    return AuditJournal(path).append(f"run-{index}", {"state": "DONE", "index": index})["sequence"]


class JournalTests(unittest.TestCase):
    def test_append_and_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = AuditJournal(Path(directory) / "events.jsonl")
            event = journal.append("run-1", {"state": "DONE"})
            self.assertEqual(journal.replay()[0]["hash"], event["hash"])

    def test_repeated_run_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = AuditJournal(Path(directory) / "events.jsonl")
            first = journal.append("run-1", {"state": "DONE"})
            second = journal.append("run-1", {"state": "DONE"})
            self.assertEqual(first, second)
            self.assertEqual(len(journal.replay()), 1)

    def test_changed_run_is_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = AuditJournal(Path(directory) / "events.jsonl")
            journal.append("run-1", {"state": "DONE"})
            with self.assertRaisesRegex(JournalError, "idempotency conflict"):
                journal.append("run-1", {"state": "FAILED"})

    def test_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = AuditJournal(path)
            journal.append("run-1", {"state": "DONE"})
            event = json.loads(path.read_text(encoding="utf-8"))
            event["report"]["state"] = "FAILED"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(JournalError, "hash mismatch"):
                journal.replay()

    def test_missing_journal_is_not_reported_as_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(JournalError, "does not exist"):
                AuditJournal(Path(directory) / "missing.jsonl").replay()

    def test_idempotency_is_type_sensitive_and_json_is_finite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = AuditJournal(Path(directory) / "events.jsonl")
            journal.append("typed", {"value": True})
            with self.assertRaisesRegex(JournalError, "idempotency conflict"):
                journal.append("typed", {"value": 1})
            with self.assertRaisesRegex(JournalError, "strict JSON"):
                journal.append("nan", {"value": float("nan")})

    def test_size_limit_is_fenced_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = AuditJournal(Path(directory) / "events.jsonl")
            with patch("repo_doctor_ai.journal.MAX_JOURNAL_BYTES", 700):
                journal.append("first", {"value": "small"})
                with self.assertRaisesRegex(JournalError, "would exceed"):
                    journal.append("second", {"value": "x" * 500})
                self.assertEqual(len(journal.replay()), 1)

    def test_missing_final_newline_is_rejected_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            journal = AuditJournal(path)
            journal.append("first", {"state": "DONE"})
            path.write_bytes(path.read_bytes().removesuffix(b"\n"))
            with self.assertRaisesRegex(JournalError, "end with a newline"):
                journal.replay()
            with self.assertRaisesRegex(JournalError, "end with a newline"):
                journal.append("second", {"state": "DONE"})
            self.assertNotIn(b"}{", path.read_bytes())

    def test_journal_sanitizes_report_strings_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            token = "gh" + "p_" + "A" * 36
            event = AuditJournal(path).append("safe", {"evidence": token + "\x1b"})
            encoded = path.read_text(encoding="utf-8")
            self.assertNotIn(token, encoded)
            self.assertNotIn("\x1b", encoded)
            self.assertIn("[REDACTED:GITHUB_TOKEN]", event["report"]["evidence"])

    def test_process_concurrent_appends_are_contiguous(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "events.jsonl")
            with ProcessPoolExecutor(max_workers=4) as executor:
                sequences = list(executor.map(_append_concurrently, [(path, index) for index in range(24)]))
            self.assertEqual(sorted(sequences), list(range(1, 25)))
            self.assertEqual(len(AuditJournal(path).replay()), 24)


if __name__ == "__main__":
    unittest.main()
