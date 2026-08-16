# Repo Doctor AI

Repo Doctor AI is an offline, dependency-free repository auditor for engineering teams that need reproducible evidence instead of opaque quality verdicts. It inventories a repository without executing its code, applies a composable rule registry, assigns stable fingerprints, calculates a deterministic maturity score, and produces CI-ready reports, baselines, regression diffs, remediation plans, and a CycloneDX dependency inventory.

No source leaves the machine. No account, model endpoint, network connection, daemon, or database is required.

## Why it is different

- **Evidence first:** every finding contains a stable code, classification, bounded evidence, remediation, and fingerprint.
- **Truthful state:** audit reliability (`DONE`, `DEGRADED`, `WAITING`, `REJECTED`) is independent from repository result (`PASS`, `WARN`, `FAIL`).
- **Safe by construction:** repository code is never imported or executed; a pinned root descriptor and component-by-component no-follow opens confine reads; credentials and terminal controls are sanitized at the final output boundary.
- **Operational workflow:** teams can establish expiring, reasoned baselines; detect new and escalated findings; and turn results into an ordered remediation backlog.
- **Portable outputs:** text, JSON, SARIF 2.1.0, Markdown, standalone HTML, and a CycloneDX 1.5 compatible SBOM.
- **Extensible core:** trusted callers can register deterministic Python rule plugins explicitly. Repo Doctor never discovers or imports plugins from the target repository.

## Install

Python 3.11 or newer is required.

```bash
python -m pip install .
repo-doctor --version
```

For isolated CLI use:

```bash
pipx install .
```

Repo Doctor has no runtime dependencies.

## Quick start

Audit the current repository:

```bash
repo-doctor scan .
```

Write deterministic JSON and fail CI at high severity:

```bash
repo-doctor scan . \
  --format json \
  --output repo-doctor-report.json \
  --fail-on high
```

Generate human and code-scanning artifacts:

```bash
repo-doctor scan . --format markdown --output report.md --fail-on none
repo-doctor scan . --format html --output report.html --fail-on none
repo-doctor scan . --format sarif --output report.sarif --fail-on high
```

Run the bundled synthetic example:

```bash
repo-doctor scan examples/sample-repo --config examples/repo-doctor.json
```

The example is intentionally imperfect. It demonstrates findings without containing real credentials, private data, or executable untrusted code.

## Audit coverage

| Domain | Representative checks |
|---|---|
| Structure | README, license, security policy, contribution guide |
| Tests | recognized test directories and language-specific filenames |
| CI | explicit permissions, write grants, immutable action SHAs, risky triggers, event-to-shell interpolation |
| Dependencies | Python requirements and `pyproject.toml`, npm, Go, Rust, Docker base-image policy, lock/checksum presence |
| Secrets | private keys, GitHub/AWS shapes, credential assignments, high-entropy credential-named literals; values always redacted |
| Repository policy | generated artifacts, vendored source, oversized review surfaces |
| Ownership | CODEOWNERS, maintainers/governance documentation |
| Documentation | architecture and operational/runbook coverage |
| Release | changelog presence and cross-manifest version consistency |
| Debt | unfinished-work markers, bare Python exception handlers, dynamic execution, oversized source modules |

List the complete diagnostic catalog and active plugins:

```bash
repo-doctor rules
repo-doctor rules --format json
repo-doctor explain CI_ACTION_NOT_FULL_SHA
```

These rules provide deterministic signals, not a substitute for human review, runtime testing, vulnerability feeds, license counsel, or a malware sandbox.

## Score and maturity

The report includes an explicit 0–100 score. Active findings subtract fixed severity weights: critical 25, high 12, medium 5, low 2, and informational 0. An incomplete audit subtracts 20. Scores map to stable bands:

| Score | Maturity |
|---:|---|
| 90–100 | optimized |
| 75–89 | managed |
| 55–74 | defined |
| 30–54 | developing |
| 0–29 | initial |

The score is a prioritization aid, not a security certification. When a baseline suppresses findings, reports retain both the active score and `raw_value`, which includes suppressed debt.

## Reviewed baselines and suppressions

First produce a report, then create a baseline. Every baseline entry requires a human-readable reason and can expire:

```bash
repo-doctor scan . --format json --output before.json --fail-on none
repo-doctor baseline before.json \
  --output repo-doctor-baseline.json \
  --reason "Accepted during the Q4 migration; tracked in issue 418" \
  --expires 2026-12-31
repo-doctor scan . \
  --baseline repo-doctor-baseline.json \
  --format json \
  --output after.json
```

Only an exact fingerprint and diagnostic-code match can suppress a finding. Expired entries remain active and are counted in `expired_suppressions`. Suppressed findings remain visible under `suppressed_findings`, including reason and expiry. Baselines cannot turn an incomplete scan into a verified one.

## Regression diffs

Compare active findings across two reports:

```bash
repo-doctor diff main.json candidate.json
repo-doctor diff main.json candidate.json \
  --format json \
  --output regression.json \
  --fail-on-regression
```

The diff classifies new, resolved, unchanged, and severity-escalated findings by fingerprint. `--fail-on-regression` exits 1 for a new or escalated signal, which makes the command suitable for pull-request quality gates.

## Remediation planning

Turn a JSON report into deterministic work items grouped by rule:

```bash
repo-doctor plan report.json --output remediation.md
repo-doctor plan report.json --format json --output remediation.json
```

Each item includes priority, response window, severity, category, estimated effort, affected fingerprints and locations, a recommended action, and a fresh-scan acceptance criterion.

## Offline SBOM

Generate a bounded CycloneDX 1.5 compatible manifest inventory:

```bash
repo-doctor sbom . --output repo-doctor.cdx.json
```

The inventory reads Python, npm, Go, Rust, and Docker manifests. It does not resolve dependency graphs, contact registries, execute package managers, or claim vulnerability status. Malformed supported manifests reject the SBOM instead of silently producing an incomplete inventory. Direct dependency URLs are represented as `direct-url-redacted`, and credential-shaped component data is sanitized.

## Configuration and resource bounds

Generate the default configuration:

```bash
repo-doctor init repo-doctor.json
```

```json
{
  "config_version": "1.0",
  "exclude": [
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "node_modules",
    "build", "dist", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"
  ],
  "max_files": 10000,
  "max_file_bytes": 1048576,
  "max_total_bytes": 67108864,
  "timeout_seconds": 30,
  "error_threshold": 20,
  "max_findings": 5000,
  "enabled_categories": [
    "structure", "tests", "ci", "dependencies", "secrets", "todos", "debt",
    "repository", "ownership", "documentation", "release"
  ]
}
```

Unknown fields, duplicate JSON keys, unsafe excludes, unknown categories, and values outside documented limits are rejected. The public `Config(...)` constructor enforces the same numeric and path invariants while permitting safe custom plugin categories. Limit exhaustion produces a blocked state rather than a false all-clear.

## Audit state and exit codes

`state` describes whether the audit completed reliably. `result` describes the repository findings.

| State | Status | Meaning |
|---|---|---|
| `DONE` | `verified` | configured inventory and rules completed |
| `DEGRADED` | `blocked` | one or more recoverable filesystem errors occurred |
| `WAITING` | `blocked` | time, file-count, total-byte, or finding bound stopped the audit |
| `REJECTED` | `blocked` | root validation failed or the error circuit opened |

| Exit | Meaning |
|---:|---|
| 0 | audit completed and no active finding met `--fail-on` |
| 1 | audit completed and an active finding met `--fail-on`; also used by regression gating |
| 2 | audit did not complete with verified status |
| 3 | configuration, artifact, journal, output, or invocation error |

Use `--fail-on none` for reporting-only mode.

## Journal and replay

Persist hash-chained, idempotent audit evidence:

```bash
repo-doctor scan . \
  --format json \
  --journal .repo-doctor/events.jsonl \
  --run-id pr-42-attempt-1
repo-doctor replay .repo-doctor/events.jsonl --json
```

Repeating the same run identifier and canonical typed report returns the existing event. Reusing a run identifier with changed results is an idempotency conflict. Cooperating processes are serialized with an OS file lock, event/journal byte limits are checked before append, and a missing final newline rejects replay and append. The CLI rejects an output path that aliases the journal or its lock. The journal is tamper-evident, not cryptographically signed; retain a trusted head hash externally for stronger assurance.

## Trusted rule plugins

The Python API supports explicit plugin registration:

```python
from repo_doctor_ai import Config, Finding, RulePlugin, RuleRegistry, Scanner

def audit_policy(files):
    if any(getattr(file, "path", "") == "POLICY.md" for file in files):
        return []
    return [
        Finding(
            "ORG_POLICY_MISSING", "organization", "medium", "proof",
            "The organization policy file is missing.",
            "Add the reviewed POLICY.md file.", evidence="root inventory",
        )
    ]

registry = RuleRegistry([
    RulePlugin("organization.policy", "organization", "Organization policy", audit_policy)
])
report = Scanner(
    Config(enabled_categories=("organization",)),
    registry=registry,
).scan(".")
```

Plugins are trusted application code. Repo Doctor never loads plugins from the repository under audit and never catches contract violations as successful scans. Exact duplicate findings are collapsed and conflicting identities are rejected. File iteration and finding collection enforce the scan deadline; POSIX main-thread scans also preempt a rule that blocks before yielding. See [Rule plugins](docs/RULE_PLUGINS.md).

## Privacy and security

Potential credentials are redacted at finding construction and again at every persisted/output string boundary, including paths, plugin findings, journals, and SBOM components. C0/C1 controls are rendered inert and SARIF paths are URI-encoded. Reports retain only diagnostic type, sanitized location, match length, and bounded statistical evidence. Paths and findings can still reveal sensitive engineering context, so protect all outputs.

The scanner does not make untrusted source safe to execute. It does not inspect Git history, resolve encoded or encrypted secrets, query advisories, or prove that a token is live. See [Security policy](SECURITY.md), [Architecture](docs/ARCHITECTURE.md), and [report contract](SPEC.md).

## Development

```bash
python scripts/check.py
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir /tmp/wheels
repo-doctor scan . --fail-on critical
repo-doctor sbom . --output /tmp/repo-doctor.cdx.json
```

Contributions are welcome under Apache-2.0. Tests and issue reproductions must use synthetic data only.
