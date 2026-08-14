# Decision log

## D-001 — Offline deterministic core

Version 0.1.0 uses explicit local rules and no model endpoint. This makes evidence reproducible, keeps source on the user's machine, avoids account setup, and gives later recommendation layers a trustworthy fact base.

## D-002 — Separate scan state from repository result

A completed audit can correctly find serious problems. Therefore `state/status` describes audit reliability while `result` describes findings. Errors can never masquerade as successful completion.

## D-003 — Redact credential matches at construction

Rules return match type and length instead of matched content. Redaction is not a presentation toggle, so JSON, text, SARIF, journals, and Python callers share the same safety property.

## D-004 — Conservative bounds

Large and binary files are counted but not fully inspected. Time, file, and error limits produce inference or blockage instead of a false all-clear. Operators can raise bounds through a reviewed configuration.

## D-005 — Stable fingerprints

Fingerprints exclude message and remediation prose. They retain code, path, line, and bounded evidence so formatting improvements do not invalidate baselines.

