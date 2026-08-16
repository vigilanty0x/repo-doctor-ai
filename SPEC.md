# Repo Doctor report contract 2.0

## Audit invariant

`status == verified` if and only if the configured inventory and rule passes completed within all bounds and without operational errors. Findings and suppressions do not alter that claim; active findings determine `result` separately.

## States

- `DONE`: inventory and all enabled rule passes completed.
- `DEGRADED`: the audit continued after one or more file or walk errors.
- `WAITING`: timeout, maximum-file, or maximum-finding boundary stopped the audit.
- `REJECTED`: the root was invalid or errors reached the circuit-breaker threshold.

Only `DONE` has `status == verified`. All other states have `status == blocked` and scan CLI exit code 2.

## Results

- `PASS`: zero active findings.
- `WARN`: active findings exist, but none are high or critical.
- `FAIL`: at least one active high or critical finding exists.

CLI threshold policy is independent through `--fail-on`. A `DONE / WARN` report exits 0 under the default high threshold.

## Finding identity

Each finding has a stable code, category, severity, classification, message, remediation, optional location, bounded evidence, and 20-hex fingerprint. The fingerprint hashes only code, path, line, and evidence. It excludes severity and prose so escalation can be detected and editorial improvements do not churn baseline identity.

Classifications:

- `proof`: directly observed by the completed pass;
- `inference`: a bounded indication that requires validation;
- `blockage`: a condition that prevents the related assurance claim.

## Score

The deterministic quality score starts at 100. Active findings subtract 25 for critical, 12 for high, 5 for medium, 2 for low, and 0 for informational severity. Any non-verified audit subtracts 20. The floor is zero.

Maturity bands are optimized (90–100), managed (75–89), defined (55–74), developing (30–54), and initial (0–29). `raw_value` applies the same formula to active plus suppressed findings. Scores are prioritization signals, not certifications.

## Baseline contract

Schema `repo-doctor-baseline/1` contains the canonical SHA-256 of its source report and up to 100,000 unique entries. An entry requires fingerprint, code, reason, and nullable ISO expiry. Reasons contain 8–500 characters.

A finding is suppressed only when fingerprint and code match and expiry is absent or not in the past. Suppressed findings are retained with their review metadata. Expired entries remain active and increment `expired_suppressions`. Baselines never alter audit state or operational errors.

## Inventory and output bounds

- Configuration: 1 MiB.
- Baseline: 4 MiB.
- Stored report consumed by diff/plan: 16 MiB.
- Journal: 64 MiB.
- Journal event: 16 MiB; append is rejected before crossing either event or journal limit.
- SBOM components: 50,000 unique normalized components.
- Files: 1 to 1,000,000; default 10,000.
- Text content per file: 1 KiB to 64 MiB; default 1 MiB.
- Total content read: 1 KiB to 4 GiB; default 64 MiB.
- Timeout: 1 to 3600 seconds; default 30.
- File errors before circuit opening: 1 to 10,000; default 20.
- Findings: 1 to 100,000; default 5,000.
- Unfinished-work findings per file: 50.
- Remediation locations retained per work item: 25.

Directories are walked in sorted order and the deadline is checked before every directory and file. Content is opened relative to a pinned root descriptor, one no-follow component at a time. Configured paths, directory symlinks, and file symlinks are not followed; a component swap fails as an unreadable blockage instead of escaping the root. Platforms without descriptor-relative opens fail closed. Binary files are counted but not decoded. Oversized files produce an inference and are not inspected.

## Secret evidence policy

Credential-shaped match content is prohibited in all report, journal, and SBOM string fields. A shared final sanitizer covers findings from every rule/plugin, paths, suppression reasons, stored journal reports, and component metadata. C0/C1 controls are escaped visibly and SARIF artifact locations are URI-encoded. Evidence records only redacted type, length, and for entropy signals a rounded statistic. Location is retained for remediation. Pattern and entropy matching are defensive signals, not proof that a value is live.

## Rule registry

Plugins are explicitly registered trusted Python callables. The scanner never imports a plugin from the target repository. Plugins execute in sorted stable-name order. The registry validates finding type, category, severity, classification, safe output text, and fingerprint uniqueness. Exact duplicates collapse; conflicting duplicates are invocation failures. Deadline checks wrap plugins, file iteration, and yielded findings; POSIX main-thread scans additionally use a process timer to interrupt a blocking rule.

## Diff contract

Schema `repo-doctor-diff/1` compares active findings by fingerprint and returns new, resolved, unchanged, and severity-escalated counts plus evidence. `regression` is true when a finding is new or severity escalates.

## Remediation-plan contract

Schema `repo-doctor-remediation-plan/1` groups active findings by code. Work items include deterministic priority, response window, highest severity, category, count, action, acceptance criterion, effort band, fingerprints, and up to 25 sorted locations.

## SBOM contract

The SBOM is a deterministic CycloneDX 1.5 compatible manifest inventory. It covers supported Python, npm, Go, Rust, and Docker declarations without resolving transitive dependencies or contacting registries. Invalid JSON/TOML and structurally invalid dependency sections reject generation. Direct URLs are masked and credential-shaped component fields are sanitized. It does not claim vulnerability, license, or reachability status.

## Journal

Journal events contain event ID, caller run ID, one-based sequence, UTC timestamp, sanitized report, previous hash, and event hash. Replay verifies exact fields, strict finite JSON, final newline, unique run IDs, sequence, link, safe strings, and SHA-256 content hash. A companion OS lock serializes cooperating processes, append is size-fenced before the write, and idempotency compares canonical typed JSON. The CLI rejects report-output aliases to the journal and lock. The journal is tamper-evident, not signed; non-cooperating direct file writers remain outside the trust boundary.

## Rollback and uninstall

Repo Doctor never modifies the scanned repository unless a caller explicitly selects an output or journal path inside it. Uninstall the Python package and remove optional artifacts. There is no remote account, daemon, database, telemetry, or migration to reverse.
