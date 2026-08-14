# Repo Doctor AI

Repo Doctor AI is a local, dependency-free repository auditor. It inspects structure, tests, CI, dependencies, credential-shaped values, TODOs, and technical debt, then returns stable findings with reproducible evidence and concrete remediation.

The first release is deliberately deterministic: no source code leaves the machine, no account is required, and no remote model is called. “AI” describes the assistant-friendly report contract and documented construction process, not an opaque verdict.

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

## Quick start

Audit the current repository:

```bash
repo-doctor scan .
```

Produce deterministic JSON and fail CI at high severity:

```bash
repo-doctor scan . --format json --output repo-doctor-report.json --fail-on high
```

Create a GitHub code-scanning compatible SARIF document:

```bash
repo-doctor scan . --format sarif --output repo-doctor.sarif --fail-on critical
```

Run the bundled synthetic example:

```bash
repo-doctor scan examples/sample-repo --config examples/repo-doctor.json
```

The example is intentionally imperfect, so the report demonstrates evidence and recommendations without containing real credentials or private data.

## What it audits

| Category | Examples | Evidence |
|---|---|---|
| Structure | README, license, security policy, contribution guide | bounded root inventory |
| Tests | recognized test directories and filenames | exact path inventory |
| CI | missing workflows, `pull_request_target`, moving action refs | file and line |
| Dependencies | unpinned requirements, moving package versions | declaration and line where available |
| Secrets | private-key, GitHub-token, AWS-key, and credential-assignment shapes | path, line, type, and length; value always redacted |
| TODOs | TODO and FIXME markers | path, line, marker only |
| Debt | bare `except`, dynamic execution, very large Python modules | path, line, bounded fact |

Every finding is classified:

- `proof`: directly observed by a completed scan.
- `inference`: a bounded limitation, such as a file skipped by size policy.
- `blockage`: an error or unsafe condition that prevents a complete claim.

## State and result are separate

`state` describes whether the audit completed reliably. `result` describes the repository findings.

| State | Meaning |
|---|---|
| `DONE` | The configured audit completed; status is `verified` |
| `DEGRADED` | Recoverable file errors occurred; status is `blocked` |
| `WAITING` | Timeout or file limit stopped the scan; status is `blocked` |
| `REJECTED` | The root is invalid or the error circuit opened; status is `blocked` |

A repository can therefore be `DONE / FAIL`: the audit itself completed correctly and found high-severity problems. Errors are never converted into successful audit completion.

## Stable exit codes

| Code | Meaning |
|---:|---|
| 0 | Audit completed and no finding met `--fail-on` |
| 1 | Audit completed and a finding met `--fail-on` |
| 2 | Audit did not complete with verified status |
| 3 | Configuration, journal, output, or invocation error |

Use `--fail-on none` for reporting-only mode.

## Bounded configuration

Generate the default configuration:

```bash
repo-doctor init repo-doctor.json
```

```json
{
  "config_version": "1.0",
  "exclude": [".git", ".venv", "node_modules", "build", "dist", "__pycache__"],
  "max_files": 10000,
  "max_file_bytes": 1048576,
  "timeout_seconds": 30,
  "error_threshold": 20,
  "enabled_categories": ["structure", "tests", "ci", "dependencies", "secrets", "todos", "debt"]
}
```

Unknown fields, duplicate JSON keys, unsafe exclude paths, unknown categories, and values outside documented limits are rejected.

## Journal and idempotency

For auditable runs, provide both a journal and a stable run identifier:

```bash
repo-doctor scan . \
  --format json \
  --journal .repo-doctor/events.jsonl \
  --run-id pr-42-attempt-1
repo-doctor replay .repo-doctor/events.jsonl --json
```

Events form a canonical SHA-256 chain. Repeating the same run identifier and logical report returns the existing event. Reusing it for changed results is an idempotency conflict.

## Privacy and security

The scanner is offline and only reads inside the resolved audit root. It does not follow directory symlinks. Potential credentials are never copied into evidence; reports contain only the diagnostic type, path, line, and match length. Treat reports as sensitive anyway because repository paths and findings can reveal engineering context.

See [SECURITY.md](SECURITY.md), [SPEC.md](SPEC.md), and [AI_ASSISTANCE.md](AI_ASSISTANCE.md) for the complete boundaries and provenance.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
repo-doctor scan . --fail-on critical
```

Contributions are welcome under Apache-2.0. Tests and issue reproductions must use synthetic data.

