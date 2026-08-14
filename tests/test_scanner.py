from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from repo_doctor_ai.config import Config
from repo_doctor_ai.scanner import Scanner

from tests.helpers import healthy_repo


class ScannerTests(unittest.TestCase):
    def test_healthy_synthetic_repo_completes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy_repo(root)
            report = Scanner().scan(root)
            self.assertEqual(report.state, "DONE")
            self.assertEqual(report.status, "verified")

    def test_findings_do_not_mean_scan_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "app.py").write_text("pass\n", encoding="utf-8")
            report = Scanner().scan(directory)
            self.assertEqual(report.state, "DONE")
            self.assertEqual(report.result, "FAIL")

    def test_secret_finding_makes_result_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy_repo(root)
            value = "AK" + "IA" + "A" * 16
            (root / "bad.txt").write_text(value, encoding="utf-8")
            report = Scanner().scan(root)
            self.assertTrue(any(finding.code == "SECRET_AWS_ACCESS_KEY" for finding in report.findings))
            self.assertEqual(report.result, "FAIL")

    def test_excluded_directory_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy_repo(root)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "bad.py").write_text("eval('1')", encoding="utf-8")
            report = Scanner().scan(root)
            self.assertFalse(any(finding.path and "node_modules" in finding.path for finding in report.findings))

    def test_large_file_is_classified_as_inference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy_repo(root)
            (root / "large.txt").write_text("x" * 2048, encoding="utf-8")
            report = Scanner(Config(max_file_bytes=1024)).scan(root)
            finding = next(f for f in report.findings if f.code == "SCAN_FILE_SKIPPED_LARGE")
            self.assertEqual(finding.classification, "inference")

    def test_binary_file_is_counted_without_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy_repo(root)
            (root / "image.bin").write_bytes(b"\x00\xff")
            report = Scanner().scan(root)
            self.assertEqual(report.metrics["binary_files"], 1)

    def test_file_limit_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_text("1", encoding="utf-8")
            (root / "two").write_text("2", encoding="utf-8")
            report = Scanner(Config(max_files=1)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("WAITING", "FILE_LIMIT"))

    def test_timeout_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_text("1", encoding="utf-8")
            times = iter((0.0, 2.0, 2.0))
            report = Scanner(Config(timeout_seconds=1), clock=lambda: next(times, 2.0)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("WAITING", "TIMEOUT"))

    def test_error_threshold_opens_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_text("1", encoding="utf-8")
            with patch.object(Path, "read_bytes", side_effect=OSError("synthetic")):
                report = Scanner(Config(error_threshold=1)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("REJECTED", "CIRCUIT_OPEN"))

    def test_invalid_root_is_rejected(self) -> None:
        report = Scanner().scan("/not/a/real/repository")
        self.assertEqual((report.state, report.reason_code), ("REJECTED", "ROOT_INVALID"))

    def test_report_order_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z.py").write_text("# TODO\n", encoding="utf-8")
            (root / "a.py").write_text("# FIXME\n", encoding="utf-8")
            first = Scanner().scan(root).as_dict()
            second = Scanner().scan(root).as_dict()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

