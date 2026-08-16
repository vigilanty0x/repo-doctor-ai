# Architecture

## System boundary

Repo Doctor is a single-process, offline Python application. The only required input is a filesystem directory. The core never executes repository code, imports inspected modules, invokes a package manager, loads a model, or opens a network connection.

```text
repository + strict config + optional baseline
                    |
                    v
        bounded deterministic inventory
                    |
                    v
        trusted explicit RuleRegistry
                    |
                    v
        findings -> baseline filter -> score/result
                    |
          +---------+---------+
          |         |         |
        reports   journal   operators
       text/json  hash chain baseline/diff/plan/SBOM
       SARIF/md/html
```

## Components

| Module | Responsibility | Trust boundary |
|---|---|---|
| `config.py` | strict JSON configuration and bounds | rejects duplicate keys, unknown fields, unsafe excludes |
| `scanner.py` | sorted inventory, content classification, root containment, state machine | pinned root descriptor; every component opened no-follow |
| `registry.py` | explicit plugin registration, ordering, finding-contract validation | plugin code is trusted caller code, never target-repository code |
| `rules.py` | built-in deterministic audits | parses text/JSON/TOML only; no execution |
| `baseline.py` | reasoned/expiring fingerprint suppressions | exact fingerprint and code match required |
| `models.py` | finding identity, score, maturity, report serialization | prose changes do not churn fingerprints |
| `reporting.py` | text, JSON, SARIF, Markdown, HTML | global credential/control sanitization, HTML escaping, URI-safe SARIF paths |
| `diffing.py` | report validation and regression comparison | bounded input, duplicate fingerprints rejected |
| `planning.py` | deterministic remediation grouping | no automated source modification |
| `sbom.py` | bounded manifest-only CycloneDX inventory | no package resolution or registry lookup |
| `journal.py` | append-only idempotent hash chain and replay | OS-lock serialized across cooperating processes; tamper-evident, not signed |

## Inventory flow

1. Resolve and validate the root.
2. Walk directories in sorted order with `followlinks=False`.
3. Pin the resolved root directory descriptor and fail closed if descriptor-relative opens are unavailable.
4. Prune configured paths and all directory symlinks.
5. Skip all file symlinks and retain an inference finding.
6. Reopen each file component-by-component relative to the pinned root with no-follow flags.
7. Enforce file-count, content-size, per-directory/rule deadline, error, and finding limits.
8. Treat NUL-bearing content as binary; decode other content as UTF-8 with replacement.
9. Run enabled trusted plugins in stable name order.
10. Sanitize and validate every plugin finding, deduplicating only exact identities.
11. Sort findings by severity, category, location, code, and fingerprint.
12. Apply an optional non-expired baseline, then calculate result and score.

Limit exhaustion is a blocked `WAITING` state. Filesystem errors are `DEGRADED` until the configured circuit opens, at which point the state is `REJECTED`. A baseline changes active findings but never audit state.

## Identity and compatibility

A finding fingerprint hashes sanitized `code`, `path`, `line`, and bounded `evidence`. It intentionally excludes severity, message, and remediation so editorial changes and severity escalation remain comparable. Fingerprints are 20 lowercase hexadecimal characters.

Report version 2.0 adds score and suppression details while retaining the version 1 fields. Stored reports consumed by baseline, diff, and plan commands must match the exact v2 field topology; unknown fields, ambiguous JSON, inconsistent summaries, and stale fingerprints are rejected. Stable diagnostic codes are compatibility surfaces. Removing or redefining a code requires a release note and migration guidance.

## Determinism

Determinism is preserved through sorted walks, sorted plugins, stable report ordering, canonical JSON hashes, fixed scoring weights, no runtime network data, and no timestamps in generated reports, diffs, plans, or SBOMs. Journal events intentionally include an event identifier and UTC time; journal idempotency compares the logical report, not newly generated metadata.

## Failure and recovery

- Invalid root: correct the path and rerun.
- Limit reached: review and raise only the relevant bound, or narrow the audit root.
- File error: repair permissions or exclude the reviewed path; never interpret `DEGRADED` as clean.
- Plugin contract error: fix the trusted plugin. Contract errors propagate to the caller/CLI as invocation errors.
- Invalid baseline/report/journal: regenerate from a trusted report; never edit hashes manually.
- Interrupted artifact write: atomic report writes preserve the prior complete file.

Repo Doctor itself is read-only except for explicitly selected output, baseline, report, SBOM, and journal paths.
