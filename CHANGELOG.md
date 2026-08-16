# Changelog

## 0.2.0 - 2026-08-16

- Add an explicit composable rule registry with trusted plugin contracts and deterministic execution.
- Expand CI checks to least-privilege permissions, full action SHAs, risky triggers, and event-to-shell interpolation.
- Expand manifest policy across Python, npm, Go, Rust, and Docker, including parse blockages and lock/checksum signals.
- Add redacted high-entropy credential signals plus generated, vendor, large-file, ownership, documentation, and release hygiene rules.
- Add deterministic 0–100 scoring, maturity bands, raw debt score, reasoned baselines, and suppression expiry.
- Add report regression diffs and evidence-linked remediation plans.
- Add Markdown and standalone HTML reports plus an offline CycloneDX 1.5 compatible SBOM.
- Add file-symlink skipping, global byte/finding bounds, expanded artifact validation, and a 104-test source/artifact suite.
- Pin GitHub Actions to reviewed full commit SHAs and add wheel, HTML, and SBOM CI checks.
- Harden public artifacts with bounded no-follow reads, strict finite JSON, exact consumed-report schemas, and a process-safe size-fenced journal.
- Close ancestor-symlink races with pinned descriptor-relative reads for scanner and SBOM inputs.
- Apply credential redaction and control-character neutralization across every finding/output sink, URI-encode SARIF paths, and mask SBOM direct URLs.
- Enforce per-directory and rule deadlines, deterministic plugin-finding deduplication, semantic report validation, strict journal line termination, and output/journal alias rejection.
- Reject malformed supported SBOM manifests and build/install both wheel and sdist in CI.

## 0.1.0 - 2026-08-15

- Add deterministic local audits for structure, tests, CI, dependencies, secrets, TODOs, and Python debt.
- Add proof, inference, and blockage classifications with stable findings and redacted secret evidence.
- Add explicit audit states, timeouts, file bounds, resolved-root protection, and an error circuit breaker.
- Add JSON, text, and SARIF output plus atomic file writes.
- Add an append-only, hash-chained journal with idempotent run IDs.
- Add synthetic demo, tests, security policy, specification, decision log, and AI assistance disclosure.
