# Decision log

## D-001 — Offline deterministic core

Version 0.1.0 uses explicit local rules and no model endpoint. This makes evidence reproducible, keeps source on the user's machine, avoids account setup, and gives later recommendation layers a trustworthy fact base.

## D-002 — Separate scan state from repository result

A completed audit can correctly find serious problems. Therefore `state/status` describes audit reliability while `result` describes findings. Errors can never masquerade as successful completion.

## D-003 — Redact at construction and at the final output boundary

Rules return match type and length instead of matched content. A shared sanitizer is also applied to all finding fields, persisted journal values, and SBOM components so another rule or plugin cannot re-emit the same credential. Control characters are rendered inert and SARIF paths are URI-encoded. Redaction is not a presentation toggle, so JSON, text, SARIF, journals, and Python callers share the same safety property.

## D-004 — Conservative bounds

Large and binary files are counted but not fully inspected. Time, file, and error limits produce inference or blockage instead of a false all-clear. Operators can raise bounds through a reviewed configuration.

## D-005 — Stable fingerprints

Fingerprints exclude message and remediation prose. They retain code, path, line, and bounded evidence so formatting improvements do not invalidate baselines.

## D-006 — Explicit trusted plugin registry

Extensibility is an in-process API, not discovery from the scanned repository. This preserves the no-execution boundary while allowing organizations to compose deterministic policy rules. A plugin contract violation fails visibly.

## D-007 — Suppressions remain visible debt

Baselines require a reason and optional expiry, match exact fingerprint plus code, and preserve suppressed findings in reports. Active and raw scores prevent a baseline from presenting accepted debt as absent.

## D-008 — Manifest-only SBOM

The core emits a deterministic CycloneDX-compatible inventory without package-manager execution or registry access. This is useful as local evidence but intentionally does not claim a fully resolved graph, vulnerability status, or legal conclusion.

## D-009 — Conservative symlink policy

All file and directory symlinks are skipped, even when they currently resolve inside the root. A root directory descriptor is pinned and each content path is opened one no-follow component at a time, closing ancestor-swap races between containment checks and reads. Platforms without descriptor-relative opens fail closed.

## D-010 — Exact artifact semantics

Consumed reports are validated as complete semantic objects: state, status, reason, result, score, counts, fingerprints, suppression topology, and safe strings must agree. Journals reject a missing final newline before append, and CLI output paths may not alias their journal or lock. Ambiguous artifacts fail instead of being repaired implicitly.
