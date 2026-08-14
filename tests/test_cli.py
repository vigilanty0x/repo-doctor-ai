from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from repo_doctor_ai.cli import main

from tests.helpers import healthy_repo


class CliTests(unittest.TestCase):
    def test_init_writes_valid_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doctor.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init", str(path)]), 0)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["config_version"], "1.0")

    def test_json_scan_and_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy_repo(root)
            journal = root.parent / f"{root.name}-journal.jsonl"
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "scan",
                        str(root),
                        "--format",
                        "json",
                        "--journal",
                        str(journal),
                        "--run-id",
                        "cli-run-1",
                        "--fail-on",
                        "critical",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["state"], "DONE")
            self.assertTrue(journal.exists())

    def test_high_finding_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "app.py").write_text("pass\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan", directory, "--format", "json"]), 1)

    def test_sarif_output_has_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "app.py").write_text("# TODO\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                main(["scan", directory, "--format", "sarif", "--fail-on", "none"])
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "Repo Doctor AI")

    def test_rules_and_explain(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["rules"]), 0)
            self.assertEqual(main(["explain", "TESTS_MISSING"]), 0)
        self.assertIn("TESTS_MISSING", output.getvalue())

    def test_unknown_rule_returns_three(self) -> None:
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["explain", "NOT_REAL"]), 3)

    def test_journal_and_run_id_are_paired(self) -> None:
        with tempfile.TemporaryDirectory() as directory, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan", directory, "--journal", "events.jsonl"]), 3)


if __name__ == "__main__":
    unittest.main()

