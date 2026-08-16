from __future__ import annotations

import unittest

from repo_doctor_ai.rules import (
    SourceFile,
    audit_ci,
    audit_dependencies,
    audit_documentation,
    audit_ownership,
    audit_release,
    audit_repository,
    audit_secrets,
)


class AdvancedRuleTests(unittest.TestCase):
    def test_ci_checks_full_sha_permissions_and_shell_interpolation(self) -> None:
        workflow = """on:
  pull_request_target:
permissions:
  contents: write
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: echo '${{ github.event.pull_request.title }}'
"""
        codes = {finding.code for finding in audit_ci((SourceFile(".github/workflows/ci.yml", len(workflow), workflow),))}
        self.assertTrue(
            {"CI_PULL_REQUEST_TARGET", "CI_ACTION_NOT_FULL_SHA", "CI_PERMISSION_WRITE", "CI_UNTRUSTED_INTERPOLATION"}.issubset(codes)
        )

    def test_full_sha_and_read_permissions_are_accepted(self) -> None:
        sha = "a" * 40
        workflow = f"permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{sha}\n"
        self.assertEqual(audit_ci((SourceFile(".github/workflows/ci.yml", len(workflow), workflow),)), [])

    def test_multiline_event_interpolation_is_detected(self) -> None:
        workflow = """permissions: {}
jobs:
  test:
    steps:
      - run: |
          echo "${{ github.event.issue.title }}"
"""
        findings = audit_ci((SourceFile(".github/workflows/ci.yml", len(workflow), workflow),))
        signal = next(finding for finding in findings if finding.code == "CI_UNTRUSTED_INTERPOLATION")
        self.assertEqual(signal.line, 6)

    def test_manifest_ecosystems_and_docker_are_checked(self) -> None:
        files = (
            SourceFile("web/package.json", 20, '{"dependencies":{"left-pad":"latest"}}'),
            SourceFile("go.mod", 40, "module example.test/demo\nrequire example.test/lib v1.0.0\n"),
            SourceFile("Cargo.toml", 30, '[dependencies]\nserde = "*"\n'),
            SourceFile("Dockerfile", 20, "FROM python:3.12\n"),
        )
        findings = audit_dependencies(files)
        codes = {finding.code for finding in findings}
        self.assertIn("DEPENDENCY_UNPINNED", codes)
        self.assertIn("DEPENDENCY_LOCK_MISSING", codes)
        self.assertIn("DOCKER_BASE_UNPINNED", codes)

    def test_sibling_npm_lockfile_satisfies_lock_policy(self) -> None:
        files = (
            SourceFile("web/package.json", 20, '{"dependencies":{"demo":"1.0.0"}}'),
            SourceFile("web/package-lock.json", 2, "{}"),
        )
        self.assertFalse(any(finding.code == "DEPENDENCY_LOCK_MISSING" for finding in audit_dependencies(files)))

    def test_npm_range_is_an_explicit_inference(self) -> None:
        files = (
            SourceFile("package.json", 30, '{"dependencies":{"demo":"^1.2.3"}}'),
            SourceFile("package-lock.json", 2, "{}"),
        )
        finding = next(finding for finding in audit_dependencies(files) if finding.code == "DEPENDENCY_UNPINNED")
        self.assertEqual((finding.severity, finding.classification), ("low", "inference"))

    def test_invalid_manifest_is_a_blockage_without_content_echo(self) -> None:
        sensitive = "{" + "not-json-secret-value"
        finding = audit_dependencies((SourceFile("package.json", len(sensitive), sensitive),))[0]
        self.assertEqual((finding.code, finding.classification), ("DEPENDENCY_MANIFEST_INVALID", "blockage"))
        self.assertNotIn(sensitive, finding.evidence or "")

    def test_structurally_invalid_manifest_types_do_not_crash(self) -> None:
        files = (
            SourceFile("package.json", 2, "[]"),
            SourceFile("pyproject.toml", 20, 'project = "invalid"\n'),
        )
        findings = audit_dependencies(files)
        self.assertEqual([finding.code for finding in findings], ["DEPENDENCY_MANIFEST_INVALID", "DEPENDENCY_MANIFEST_INVALID"])

    def test_high_entropy_secret_evidence_is_redacted(self) -> None:
        candidate = "aB3dE5fG7hJ9kL2m" + "N4pQ6rS8tU0vW1xY"
        text = f'auth_token="{candidate}"'
        findings = audit_secrets((SourceFile("settings.ini", len(text), text),))
        self.assertTrue(findings)
        self.assertTrue(all(candidate not in (finding.evidence or "") for finding in findings))
        self.assertTrue(all(candidate not in finding.message for finding in findings))

    def test_repository_policy_finds_generated_vendor_and_large_files(self) -> None:
        findings = audit_repository(
            (
                SourceFile("vendor/tool.js", 10, "// source"),
                SourceFile("assets/app.min.js", 10, "minified"),
                SourceFile("model.bin", 600_000, None),
            )
        )
        self.assertEqual(
            {finding.code for finding in findings},
            {"REPOSITORY_VENDOR_TRACKED", "REPOSITORY_GENERATED_TRACKED", "REPOSITORY_LARGE_FILE"},
        )

    def test_ownership_documentation_and_release_hygiene(self) -> None:
        files = (SourceFile("pyproject.toml", 40, '[project]\nversion = "1.0.0"\n'),)
        codes = {
            finding.code
            for auditor in (audit_ownership, audit_documentation, audit_release)
            for finding in auditor(files)
        }
        self.assertTrue(
            {
                "OWNERSHIP_CODEOWNERS_MISSING",
                "OWNERSHIP_MAINTAINERS_MISSING",
                "DOCUMENTATION_ARCHITECTURE_MISSING",
                "DOCUMENTATION_OPERATIONS_MISSING",
                "RELEASE_CHANGELOG_MISSING",
            }.issubset(codes)
        )

    def test_release_version_mismatch_is_deterministic(self) -> None:
        files = (
            SourceFile("pyproject.toml", 40, '[project]\nversion = "1.0.0"\n'),
            SourceFile("src/demo/__init__.py", 30, '__version__ = "2.0.0"\n'),
            SourceFile("CHANGELOG.md", 5, "# Log"),
        )
        findings = audit_release(files)
        self.assertEqual(findings[0].code, "RELEASE_VERSION_MISMATCH")
        self.assertNotIn("1.0.0", findings[0].evidence or "")


if __name__ == "__main__":
    unittest.main()
