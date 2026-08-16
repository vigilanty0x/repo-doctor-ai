from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from repo_doctor_ai.cli import main
from repo_doctor_ai.models import Finding, Report


class CliWorkflowTests(unittest.TestCase):
    def test_baseline_diff_plan_html_and_sbom_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            report = Path(directory) / "report.json"
            baseline = Path(directory) / "baseline.json"
            suppressed = Path(directory) / "suppressed.json"
            plan = Path(directory) / "plan.json"
            diff = Path(directory) / "diff.json"
            html = Path(directory) / "report.html"
            sbom = Path(directory) / "bom.json"

            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan", str(root), "--format", "json", "--output", str(report), "--fail-on", "none"]), 0)
                self.assertEqual(
                    main(
                        [
                            "baseline",
                            str(report),
                            "--output",
                            str(baseline),
                            "--reason",
                            "Reviewed synthetic migration exception",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    main(
                        [
                            "scan",
                            str(root),
                            "--baseline",
                            str(baseline),
                            "--format",
                            "json",
                            "--output",
                            str(suppressed),
                        ]
                    ),
                    0,
                )
                self.assertEqual(main(["plan", str(report), "--format", "json", "--output", str(plan)]), 0)
                self.assertEqual(main(["diff", str(report), str(suppressed), "--format", "json", "--output", str(diff)]), 0)
                self.assertEqual(main(["scan", str(root), "--format", "html", "--output", str(html), "--fail-on", "none"]), 0)
                self.assertEqual(main(["sbom", str(root), "--output", str(sbom)]), 0)

            suppressed_payload = json.loads(suppressed.read_text(encoding="utf-8"))
            self.assertEqual(suppressed_payload["findings"], [])
            self.assertGreater(suppressed_payload["summary"]["suppressed"], 0)
            self.assertGreater(json.loads(plan.read_text(encoding="utf-8"))["summary"]["work_items"], 0)
            self.assertGreater(json.loads(diff.read_text(encoding="utf-8"))["summary"]["resolved"], 0)
            self.assertIn("<!doctype html>", html.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(sbom.read_text(encoding="utf-8"))["bomFormat"], "CycloneDX")

    def test_diff_can_fail_on_regression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.json"
            current = Path(directory) / "current.json"
            finding = Finding(
                "TEST_SIGNAL", "tests", "high", "proof", "signal", "fix", evidence="fact"
            )
            base = Report("demo", "DONE", "verified", "PASS", "AUDIT_COMPLETE", (), {}, ()).as_dict()
            candidate = Report(
                "demo", "DONE", "verified", "FAIL", "AUDIT_COMPLETE", (finding,), {}, ()
            ).as_dict()
            empty.write_text(json.dumps(base), encoding="utf-8")
            current.write_text(json.dumps(candidate), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["diff", str(empty), str(current), "--fail-on-regression"]), 1)

    def test_invalid_expiry_returns_stable_invocation_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"findings": []}), encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "baseline",
                            str(report),
                            "--output",
                            str(Path(directory) / "baseline.json"),
                            "--reason",
                            "Reviewed temporary exception",
                            "--expires",
                            "not-a-date",
                        ]
                    ),
                    3,
                )


if __name__ == "__main__":
    unittest.main()
