from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from repo_doctor_ai.journal import AuditJournal, JournalError


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


if __name__ == "__main__":
    unittest.main()

