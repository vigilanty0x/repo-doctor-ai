from __future__ import annotations

import unittest

from repo_doctor_ai.rules import (
    SourceFile,
    audit_ci,
    audit_debt,
    audit_dependencies,
    audit_secrets,
    audit_structure,
    audit_tests,
    audit_todos,
)


class RuleTests(unittest.TestCase):
    def test_missing_structure_is_evidence_backed(self) -> None:
        findings = audit_structure((SourceFile("src/app.py", 1, "x"),))
        codes = {finding.code for finding in findings}
        self.assertIn("STRUCTURE_README_MISSING", codes)
        self.assertTrue(all(finding.classification == "proof" for finding in findings))

    def test_test_file_satisfies_test_inventory(self) -> None:
        self.assertEqual(audit_tests((SourceFile("tests/test_app.py", 1, "pass"),)), [])

    def test_missing_tests_is_high(self) -> None:
        finding = audit_tests((SourceFile("src/app.py", 1, "pass"),))[0]
        self.assertEqual((finding.code, finding.severity), ("TESTS_MISSING", "high"))

    def test_ci_risky_trigger_and_floating_ref(self) -> None:
        text = "on:\n  pull_request_target:\nsteps:\n  - uses: vendor/action@main\n"
        findings = audit_ci((SourceFile(".github/workflows/ci.yml", len(text), text),))
        self.assertEqual({finding.code for finding in findings}, {"CI_PULL_REQUEST_TARGET", "CI_ACTION_FLOATING_REF"})

    def test_unpinned_requirement_is_reported(self) -> None:
        findings = audit_dependencies((SourceFile("requirements.txt", 10, "requests>=2\n"),))
        self.assertEqual(findings[0].code, "DEPENDENCY_UNPINNED")

    def test_secret_is_redacted(self) -> None:
        sensitive = "gh" + "p_" + "A" * 36
        findings = audit_secrets((SourceFile("config.py", len(sensitive), sensitive),))
        self.assertEqual(findings[0].code, "SECRET_GITHUB_TOKEN")
        self.assertNotIn(sensitive, findings[0].evidence or "")
        self.assertNotIn(sensitive, findings[0].message)

    def test_generic_assignment_is_redacted(self) -> None:
        sensitive = "password=" + "'" + "a-long-fake-value" + "'"
        findings = audit_secrets((SourceFile("config.py", len(sensitive), sensitive),))
        self.assertEqual(findings[0].code, "SECRET_GENERIC_ASSIGNMENT")
        self.assertNotIn("a-long-fake-value", findings[0].evidence or "")

    def test_todo_marker_has_line(self) -> None:
        findings = audit_todos((SourceFile("app.py", 20, "ok\n# TODO: replace\n"),))
        self.assertEqual(findings[0].line, 2)

    def test_bare_except_and_eval_are_reported(self) -> None:
        source = "try:\n    pass\nexcept:\n    pass\nvalue = eval('1')\n"
        findings = audit_debt((SourceFile("app.py", len(source), source),))
        self.assertEqual({finding.code for finding in findings}, {"DEBT_BARE_EXCEPT", "DEBT_DYNAMIC_EXEC"})


if __name__ == "__main__":
    unittest.main()

