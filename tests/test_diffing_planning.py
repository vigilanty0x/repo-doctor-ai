from __future__ import annotations

import unittest
from pathlib import Path
import json
import tempfile

from repo_doctor_ai.diffing import ReportDataError, diff_reports, load_report, render_diff_markdown
from repo_doctor_ai.models import Finding, Report
from repo_doctor_ai.planning import build_plan, render_plan_markdown


def report(*findings: Finding) -> dict:
    if any(f.severity in {"high", "critical"} for f in findings):
        result = "FAIL"
    elif findings:
        result = "WARN"
    else:
        result = "PASS"
    return Report("demo", "DONE", "verified", result, "AUDIT_COMPLETE", findings, {}, ()).as_dict()


def finding(code: str, severity: str, evidence: str) -> Finding:
    return Finding(code, "ci", severity, "proof", "Problem", "Apply the reviewed fix.", "ci.yml", 4, evidence)


class DiffingAndPlanningTests(unittest.TestCase):
    def test_diff_classifies_new_resolved_and_unchanged(self) -> None:
        stable = finding("CI_STABLE", "low", "stable")
        removed = finding("CI_REMOVED", "medium", "removed")
        added = finding("CI_ADDED", "high", "added")
        result = diff_reports(report(stable, removed), report(stable, added))
        self.assertTrue(result["regression"])
        self.assertEqual(result["summary"], {"new": 1, "resolved": 1, "unchanged": 1, "severity_escalated": 0})
        self.assertIn("CI_ADDED", render_diff_markdown(result))

    def test_severity_change_uses_same_fingerprint_and_is_escalation(self) -> None:
        before = finding("CI_SIGNAL", "low", "same")
        after = finding("CI_SIGNAL", "high", "same")
        result = diff_reports(report(before), report(after))
        self.assertEqual(result["summary"]["severity_escalated"], 1)
        self.assertEqual(result["summary"]["new"], 0)
        self.assertEqual(result["summary"]["unchanged"], 0)

    def test_duplicate_fingerprints_are_rejected(self) -> None:
        item = finding("CI_SIGNAL", "low", "same")
        with self.assertRaisesRegex(ReportDataError, "duplicate"):
            diff_reports(report(item, item), report())

    def test_plan_groups_findings_and_links_acceptance(self) -> None:
        first = finding("CI_SIGNAL", "high", "one")
        second = Finding("CI_SIGNAL", "ci", "medium", "proof", "Problem", "Apply the reviewed fix.", "other.yml", 8, "two")
        plan = build_plan(report(first, second))
        self.assertEqual(plan["summary"]["work_items"], 1)
        item = plan["work_items"][0]
        self.assertEqual((item["severity"], item["count"], item["window"]), ("high", 2, "immediate"))
        self.assertIn("fresh scan", item["acceptance"])
        self.assertIn("CI_SIGNAL", render_plan_markdown(plan))

    def test_consumed_report_rejects_unknown_fields_and_identity_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            payload = report(finding("CI_SIGNAL", "high", "fact"))
            path.write_text(json.dumps({**payload, "surprise": True}), encoding="utf-8")
            with self.assertRaisesRegex(ReportDataError, "unknown fields"):
                load_report(path)
            payload["findings"][0]["evidence"] = "changed without fingerprint update"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReportDataError, "fingerprint does not match"):
                load_report(path)

    def test_consumed_report_rejects_semantic_contradictions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            base = report(finding("CI_SIGNAL", "high", "fact"))

            payload = json.loads(json.dumps(base))
            payload["status"] = "blocked"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReportDataError, "state and status"):
                load_report(path)

            payload = json.loads(json.dumps(base))
            payload["result"] = "PASS"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReportDataError, "result"):
                load_report(path)

            payload = json.loads(json.dumps(base))
            payload["score"] = {
                "value": 100,
                "raw_value": 0,
                "maturity": "optimized",
                "scale": "0-100",
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ReportDataError, "score"):
                load_report(path)


if __name__ == "__main__":
    unittest.main()
