from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from repo_doctor_ai.config import Config
from repo_doctor_ai.io_utils import BoundedReadError, ConfinedReader
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

    def test_file_symlink_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            healthy_repo(root)
            target = Path(outside) / "outside.py"
            target.write_text("eval('unsafe')\n", encoding="utf-8")
            try:
                (root / "linked.py").symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            report = Scanner().scan(root)
            self.assertEqual(report.metrics["symlink_files"], 1)
            self.assertTrue(any(finding.code == "SCAN_SYMLINK_SKIPPED" for finding in report.findings))
            self.assertFalse(any(finding.code == "DEBT_DYNAMIC_EXEC" and finding.path == "linked.py" for finding in report.findings))

    def test_file_limit_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").write_text("1", encoding="utf-8")
            (root / "two").write_text("2", encoding="utf-8")
            report = Scanner(Config(max_files=1)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("WAITING", "FILE_LIMIT"))

    def test_total_byte_limit_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.txt").write_text("x" * 800, encoding="utf-8")
            (root / "two.txt").write_text("y" * 800, encoding="utf-8")
            report = Scanner(Config(max_total_bytes=1024)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("WAITING", "BYTE_LIMIT"))
            self.assertEqual(report.metrics["bytes_read"], 800)

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
            with patch.object(
                ConfinedReader,
                "read_bounded_bytes",
                side_effect=BoundedReadError("synthetic"),
            ):
                report = Scanner(Config(error_threshold=1)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("REJECTED", "CIRCUIT_OPEN"))

    def test_ancestor_symlink_swap_cannot_escape_pinned_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            inside = root / "sub"
            inside.mkdir()
            (inside / "target.py").write_text("pass\n", encoding="utf-8")
            external = Path(outside)
            (external / "target.py").write_text("eval('outside')\n", encoding="utf-8")
            original = ConfinedReader.read_bounded_bytes

            def swap_then_read(reader, relative, maximum_bytes, **kwargs):
                if relative == "sub/target.py" and not getattr(swap_then_read, "done", False):
                    swap_then_read.done = True
                    inside.rename(root / "sub-original")
                    (root / "sub").symlink_to(external, target_is_directory=True)
                return original(reader, relative, maximum_bytes, **kwargs)

            try:
                with patch.object(ConfinedReader, "read_bounded_bytes", new=swap_then_read):
                    report = Scanner().scan(root)
            except OSError:
                self.skipTest("directory symlink creation unavailable")
            self.assertEqual(report.status, "blocked")
            self.assertFalse(any(finding.code == "DEBT_DYNAMIC_EXEC" for finding in report.findings))

    def test_timeout_is_checked_before_visiting_an_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yielded = 0

            def empty_directories(*args, **kwargs):
                nonlocal yielded
                for _ in range(100):
                    yielded += 1
                    yield str(root), [], []

            times = iter((0.0, 2.0, 2.0))
            with patch("repo_doctor_ai.scanner.os.walk", side_effect=empty_directories):
                report = Scanner(Config(timeout_seconds=1), clock=lambda: next(times, 2.0)).scan(root)
            self.assertEqual((report.state, report.reason_code), ("WAITING", "TIMEOUT"))
            self.assertEqual(yielded, 1)

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
