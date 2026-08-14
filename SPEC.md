# Repo Doctor report contract 1.0

## Audit invariant

`status == verified` if and only if the configured inventory and rule passes completed within all bounds and without operational errors. Findings do not weaken or strengthen that claim; they determine `result` separately.

## States

- `DONE`: inventory and all enabled rule passes completed.
- `DEGRADED`: the audit continued after one or more file or walk errors.
- `WAITING`: a timeout or maximum-file boundary stopped the audit.
- `REJECTED`: the root was invalid or errors reached the circuit-breaker threshold.

Only `DONE` has `status == verified`. All other states have `status == blocked` and CLI exit code 2.

## Results

- `PASS`: zero findings.
- `WARN`: findings exist, but none are high or critical.
- `FAIL`: at least one high or critical finding exists.

CLI policy is independent through `--fail-on`. For example, a `DONE / WARN` report exits 0 under the default high threshold.

## Finding identity

Each finding has a stable code, category, severity, classification, message, remediation, optional location, bounded evidence, and a 20-hex fingerprint. The fingerprint hashes only code, path, line, and evidence; it excludes prose so editorial changes do not churn suppression identity.

## Inventory bounds

- Configuration size: 1 MiB.
- Files: 1 to 1,000,000; default 10,000.
- Text file content: 1 KiB to 64 MiB; default 1 MiB.
- Timeout: 1 to 3600 seconds; default 30.
- File errors before circuit opening: 1 to 10,000; default 20.
- TODO findings per file: 50.

Directories are walked in sorted order. Excluded directories and directory symlinks are not followed. Files resolving outside the root produce a blockage. Binary files are counted but not decoded. Oversized files produce an inference finding and are not inspected.

## Secret evidence policy

Credential-shaped match content is prohibited in all report fields. Evidence records only a redacted type and character count. Location is retained for remediation. This pattern matching is a defensive signal, not proof that a value is live; users should validate and revoke safely.

## Journal

Journal events contain event ID, caller run ID, one-based sequence, UTC timestamp, full deterministic report, previous hash, and event hash. Replay verifies the exact field set, unique run IDs, sequence, link, and SHA-256 content hash. The journal is single-writer and tamper-evident, not signed; preserve the trusted head hash externally for stronger assurance.

## Rollback and uninstall

Repo Doctor never modifies the scanned repository unless the caller explicitly selects `--output` inside it. Uninstall the Python package and remove optional report/journal files. There is no remote account, daemon, database, or retained telemetry.

