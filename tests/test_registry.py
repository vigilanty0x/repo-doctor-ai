from __future__ import annotations

from pathlib import Path
import signal
import tempfile
import time
import unittest

from repo_doctor_ai.config import Config
from repo_doctor_ai.models import Finding
from repo_doctor_ai.registry import RegistryDeadlineExceeded, RegistryError, RulePlugin, RuleRegistry
from repo_doctor_ai.scanner import Scanner


def plugin_finding(category: str = "custom") -> Finding:
    return Finding("CUSTOM_SIGNAL", category, "medium", "proof", "Signal", "Fix signal", evidence="fact")


class RegistryTests(unittest.TestCase):
    def test_custom_plugin_runs_through_scanner(self) -> None:
        registry = RuleRegistry(
            [RulePlugin("custom.signal", "custom", "Synthetic trusted plugin", lambda files: [plugin_finding()])]
        )
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "file.txt").write_text("ok", encoding="utf-8")
            report = Scanner(Config(enabled_categories=("custom",)), registry=registry).scan(directory)
        self.assertEqual(report.findings[0].code, "CUSTOM_SIGNAL")
        self.assertEqual(report.metrics["rules_executed"], 1)

    def test_duplicate_plugin_name_is_rejected(self) -> None:
        plugin = RulePlugin("custom.signal", "custom", "Synthetic trusted plugin", lambda files: [])
        with self.assertRaisesRegex(RegistryError, "duplicate"):
            RuleRegistry([plugin, plugin])

    def test_plugin_description_is_sanitized_before_rules_output(self) -> None:
        token = "gh" + "p_" + "A" * 36
        plugin = RulePlugin(
            "custom.signal", "custom", f"Synthetic {token}\x1b description", lambda files: []
        )
        encoded = str(RuleRegistry([plugin]).as_dict())
        self.assertNotIn(token, encoded)
        self.assertNotIn("\x1b", encoded)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", encoded)

    def test_plugin_cannot_spoof_another_category(self) -> None:
        registry = RuleRegistry(
            [RulePlugin("custom.signal", "custom", "Synthetic trusted plugin", lambda files: [plugin_finding("ci")])]
        )
        with self.assertRaisesRegex(RegistryError, "expected"):
            registry.run((), ("custom",), max_findings=10)

    def test_finding_limit_blocks_instead_of_claiming_completion(self) -> None:
        registry = RuleRegistry(
            [
                RulePlugin(
                    "custom.signal",
                    "custom",
                    "Synthetic trusted plugin",
                    lambda files: [
                        plugin_finding(),
                        Finding("CUSTOM_OTHER", "custom", "low", "proof", "Other", "Fix", evidence="other"),
                    ],
                )
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "file.txt").write_text("ok", encoding="utf-8")
            report = Scanner(Config(enabled_categories=("custom",), max_findings=1), registry=registry).scan(directory)
        self.assertEqual((report.state, report.reason_code), ("WAITING", "FINDING_LIMIT"))
        self.assertEqual(len(report.findings), 1)

    def test_exact_duplicate_findings_are_deduplicated(self) -> None:
        finding = plugin_finding()
        registry = RuleRegistry(
            [RulePlugin("custom.duplicate", "custom", "Duplicate emitter", lambda files: [finding, finding])]
        )
        values, _, truncated = registry.run((), ("custom",), max_findings=10)
        self.assertEqual(values, [finding])
        self.assertFalse(truncated)

    def test_conflicting_duplicate_fingerprint_is_rejected(self) -> None:
        first = plugin_finding()
        second = Finding(
            first.code,
            first.category,
            "high",
            first.classification,
            "Changed severity",
            first.remediation,
            evidence=first.evidence,
        )
        registry = RuleRegistry(
            [RulePlugin("custom.conflict", "custom", "Conflicting emitter", lambda files: [first, second])]
        )
        with self.assertRaisesRegex(RegistryError, "conflicting duplicate"):
            registry.run((), ("custom",), max_findings=10)

    def test_registry_checks_deadline_during_rule_results(self) -> None:
        registry = RuleRegistry(
            [RulePlugin("custom.deadline", "custom", "Deadline emitter", lambda files: [plugin_finding()])]
        )
        times = iter((0.0, 0.0, 2.0))
        with self.assertRaises(RegistryDeadlineExceeded):
            registry.run(
                (),
                ("custom",),
                max_findings=10,
                deadline=1.0,
                clock=lambda: next(times, 2.0),
            )

    @unittest.skipUnless(hasattr(signal, "setitimer"), "hard rule deadline requires POSIX timers")
    def test_scanner_preempts_a_blocking_rule_at_deadline(self) -> None:
        def blocking(_files):
            time.sleep(2)
            return [plugin_finding()]

        registry = RuleRegistry(
            [RulePlugin("custom.blocking", "custom", "Blocking emitter", blocking)]
        )
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            report = Scanner(
                Config(enabled_categories=("custom",), timeout_seconds=1),
                registry=registry,
            ).scan(directory)
            elapsed = time.monotonic() - started
        self.assertEqual((report.state, report.reason_code), ("WAITING", "TIMEOUT"))
        self.assertLess(elapsed, 1.5)


if __name__ == "__main__":
    unittest.main()
