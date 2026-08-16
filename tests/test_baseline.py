from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import tempfile
import unittest

from repo_doctor_ai.baseline import Baseline, BaselineError, baseline_from_report, load_baseline
from repo_doctor_ai.models import Finding, Report
from repo_doctor_ai.scanner import Scanner


def sample_finding(severity: str = "high") -> Finding:
    return Finding(
        "TESTS_MISSING",
        "tests",
        severity,
        "proof",
        "Tests are missing.",
        "Add tests.",
        evidence="inventory",
    )


def sample_report(finding: Finding | None = None) -> Report:
    values = (finding or sample_finding(),)
    return Report("demo", "DONE", "verified", "FAIL", "AUDIT_COMPLETE", values, {}, ())


class BaselineTests(unittest.TestCase):
    def test_round_trip_and_suppression(self) -> None:
        finding = sample_finding()
        baseline = baseline_from_report(
            sample_report(finding).as_dict(), reason="Accepted until migration completes", expires="2030-01-01"
        )
        active, suppressed, expired = baseline.apply((finding,), today=date(2029, 1, 1))
        self.assertEqual(active, ())
        self.assertEqual(suppressed[0].reason, "Accepted until migration completes")
        self.assertEqual(expired, ())
        self.assertEqual(Baseline.from_dict(baseline.as_dict()), baseline)

    def test_expired_entry_does_not_suppress(self) -> None:
        finding = sample_finding()
        baseline = baseline_from_report(
            sample_report(finding).as_dict(), reason="Temporary accepted migration debt", expires="2020-01-01"
        )
        active, suppressed, expired = baseline.apply((finding,), today=date(2026, 1, 1))
        self.assertEqual(active, (finding,))
        self.assertEqual(suppressed, ())
        self.assertEqual(expired[0].fingerprint, finding.fingerprint)

    def test_reason_is_mandatory_and_bounded(self) -> None:
        with self.assertRaisesRegex(BaselineError, "reason"):
            baseline_from_report(sample_report().as_dict(), reason="short")

    def test_expiry_requires_extended_iso_date(self) -> None:
        with self.assertRaisesRegex(BaselineError, "YYYY-MM-DD"):
            baseline_from_report(
                sample_report().as_dict(),
                reason="Reviewed synthetic exception",
                expires="20300101",
            )

    def test_duplicate_fingerprint_is_rejected(self) -> None:
        baseline = baseline_from_report(sample_report().as_dict(), reason="Reviewed exception reason")
        raw = baseline.as_dict()
        raw["entries"].append(dict(raw["entries"][0]))
        with self.assertRaisesRegex(BaselineError, "duplicate"):
            Baseline.from_dict(raw)

    def test_load_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text('{"schema":"x","schema":"x"}', encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "duplicate"):
                load_baseline(path)

    def test_scanner_preserves_raw_score_for_suppressed_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("pass\n", encoding="utf-8")
            first = Scanner().scan(root)
            baseline = baseline_from_report(first.as_dict(), reason="Reviewed synthetic baseline")
            second = Scanner().scan(root, baseline=baseline)
            self.assertEqual(second.findings, ())
            self.assertEqual(len(second.suppressed_findings), len(first.findings))
            self.assertEqual(second.raw_quality_score, first.quality_score)
            self.assertGreaterEqual(second.quality_score, second.raw_quality_score)

    def test_baseline_reason_is_sanitized_before_persistence(self) -> None:
        token = "gh" + "p_" + "A" * 36
        baseline = baseline_from_report(
            sample_report().as_dict(), reason=f"Accepted because {token} is rotating"
        )
        encoded = json.dumps(baseline.as_dict())
        self.assertNotIn(token, encoded)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", encoded)


if __name__ == "__main__":
    unittest.main()
