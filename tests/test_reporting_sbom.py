from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from repo_doctor_ai.config import Config
from repo_doctor_ai.models import Finding, Report
from repo_doctor_ai.io_utils import ConfinedReader
from repo_doctor_ai.reporting import render_html, render_markdown, render_sarif, serialize
from repo_doctor_ai.scanner import Scanner
from repo_doctor_ai.sbom import SbomError, build_sbom


class ReportingAndSbomTests(unittest.TestCase):
    def test_markdown_html_and_sarif_preserve_evidence_contract(self) -> None:
        finding = Finding(
            "CUSTOM_HTML",
            "ci",
            "high",
            "proof",
            "Unsafe <value>",
            "Replace | value",
            "a<b.py",
            2,
            "bounded <evidence>",
        )
        report = Report("demo", "DONE", "verified", "FAIL", "AUDIT_COMPLETE", (finding,), {}, ())
        markdown = render_markdown(report)
        html = render_html(report)
        sarif = render_sarif(report)
        self.assertIn("Replace \\| value", markdown)
        self.assertIn("a&lt;b.py", html)
        self.assertNotIn("a<b.py", html)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["fingerprints"]["repoDoctor/v2"], finding.fingerprint)

    def test_all_report_fields_redact_credentials_and_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "gh" + "p_" + "A" * 36
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {
                            token: "*",
                            ("pass" + 'word = "a very long synthetic value"'): "*",
                        }
                    }
                ),
                encoding="utf-8",
            )
            report = Scanner().scan(root)
        encoded = serialize(report, "json")
        self.assertNotIn(token, encoded)
        self.assertNotIn("a very long synthetic value", encoded)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", encoded)

        unsafe = Finding(
            "CONTROL_SIGNAL",
            "ci",
            "medium",
            "proof",
            "message\x1b]52;c;payload\x07",
            "fix",
            "space #\x1b.py",
            1,
            "evidence\nnext",
        )
        safe_report = Report("demo", "DONE", "verified", "WARN", "AUDIT_COMPLETE", (unsafe,), {}, ())
        text = serialize(safe_report, "text")
        sarif_uri = render_sarif(safe_report)["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]["uri"]
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn(" ", sarif_uri)
        self.assertNotIn("#", sarif_uri)
        self.assertIn("%20", sarif_uri)

    def test_score_and_maturity_are_deterministic(self) -> None:
        finding = Finding("X_CODE", "ci", "critical", "proof", "x", "fix")
        report = Report("demo", "DONE", "verified", "FAIL", "AUDIT_COMPLETE", (finding,), {}, ())
        self.assertEqual(report.quality_score, 75)
        self.assertEqual(report.maturity, "managed")
        self.assertEqual(report.as_dict()["score"]["value"], 75)

    def test_sbom_covers_python_npm_go_rust_and_docker_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
            (root / "package.json").write_text('{"dependencies":{"react":"19.0.0"}}', encoding="utf-8")
            (root / "go.mod").write_text("module demo\nrequire example.test/lib v1.2.3\n", encoding="utf-8")
            (root / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n', encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            first = build_sbom(root)
            second = build_sbom(root)
        self.assertEqual(first, second)
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual({item["name"] for item in first["components"]}, {"requests", "react", "example.test/lib", "serde", "python"})

    def test_sbom_respects_file_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.txt").write_text("1", encoding="utf-8")
            (root / "two.txt").write_text("2", encoding="utf-8")
            with self.assertRaisesRegex(SbomError, "max_files"):
                build_sbom(root, Config(max_files=1))

    def test_sbom_respects_total_manifest_byte_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("a==1\n" + "#" * 700, encoding="utf-8")
            (root / "requirements-dev.txt").write_text("b==1\n" + "#" * 700, encoding="utf-8")
            with self.assertRaisesRegex(SbomError, "max_total_bytes"):
                build_sbom(root, Config(max_total_bytes=1024))

    def test_sbom_rejects_invalid_package_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"dependencies": { broken', encoding="utf-8")
            with self.assertRaisesRegex(SbomError, "invalid manifest"):
                build_sbom(root)

    def test_sbom_masks_direct_urls_and_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "gh" + "p_" + "A" * 36
            (root / "requirements.txt").write_text(
                f"demo @ https://user:{token}@example.invalid/demo.whl\n", encoding="utf-8"
            )
            encoded = json.dumps(build_sbom(root))
        self.assertNotIn(token, encoded)
        self.assertNotIn("example.invalid", encoded)
        self.assertIn("direct-url-redacted", encoded)

    def test_sbom_masks_a_direct_locator_in_a_component_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"git@example.invalid:team/project.git": "main"}}),
                encoding="utf-8",
            )
            encoded = json.dumps(build_sbom(root))
        self.assertNotIn("example.invalid", encoded)
        self.assertIn("direct-url-redacted", encoded)

    def test_sbom_ancestor_symlink_swap_cannot_escape_pinned_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            inside = root / "sub"
            inside.mkdir()
            (inside / "requirements.txt").write_text("inside==1\n", encoding="utf-8")
            external = Path(outside)
            (external / "requirements.txt").write_text("outside==9\n", encoding="utf-8")
            original = ConfinedReader.read_bounded_bytes

            def swap_then_read(reader, relative, maximum_bytes, **kwargs):
                if not getattr(swap_then_read, "done", False):
                    swap_then_read.done = True
                    inside.rename(root / "sub-original")
                    (root / "sub").symlink_to(external, target_is_directory=True)
                return original(reader, relative, maximum_bytes, **kwargs)

            try:
                with patch.object(ConfinedReader, "read_bounded_bytes", new=swap_then_read):
                    with self.assertRaises(SbomError):
                        build_sbom(root)
            except OSError:
                self.skipTest("directory symlink creation unavailable")

    def test_sbom_checks_timeout_before_empty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yielded = 0

            def empty_directories(*args, **kwargs):
                nonlocal yielded
                for _ in range(100):
                    yielded += 1
                    yield str(root), [], []

            with (
                patch("repo_doctor_ai.sbom.os.walk", side_effect=empty_directories),
                patch("repo_doctor_ai.sbom.time.monotonic", side_effect=(0.0, 2.0)),
            ):
                with self.assertRaisesRegex(SbomError, "timeout_seconds"):
                    build_sbom(root, Config(timeout_seconds=1))
            self.assertEqual(yielded, 1)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_sbom_does_not_follow_file_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = Path(outside) / "requirements.txt"
            target.write_text("outside==1\n", encoding="utf-8")
            try:
                (root / "requirements.txt").symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            bom = build_sbom(root)
        self.assertEqual(bom["components"], [])


if __name__ == "__main__":
    unittest.main()
