# Security policy

## Supported versions

Security fixes are provided for the latest tagged minor release.

## Scanner boundary

Repo Doctor AI is a read-only static auditor, not a sandbox or malware scanner. Do not use it to make untrusted repositories safe to execute. The tool never runs repository code, imports inspected modules, evaluates configuration expressions, or sends source to a network service.

Controls include:

- resolved-root enforcement and no directory-symlink traversal;
- deterministic exclusions and file, content, timeout, error, and journal bounds;
- duplicate-key and unknown-field rejection for configuration;
- credential evidence redaction;
- atomic report writes;
- append-only, hash-chained, idempotent audit events;
- no runtime dependencies.

Reports can reveal filenames and security findings. Store and share them according to the repository's sensitivity. Pattern matches can be false positives or miss encoded, split, encrypted, or unfamiliar credential formats.

## Reporting a vulnerability

Use GitHub's private security advisory interface for this repository. Provide the affected version, a minimal synthetic repository, impact, and proposed mitigation. Never submit live credentials, proprietary source, or personal data.

