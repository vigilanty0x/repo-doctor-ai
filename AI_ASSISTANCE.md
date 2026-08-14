# AI assistance disclosure

## Scope

AI assistance helped draft the initial architecture, implementation, tests, documentation, and synthetic fixtures for Repo Doctor AI 0.1.0. The repository owner selected the scope, approved publication, and remains responsible for releases and maintenance.

## Human-controlled decisions

- The scanner is offline and deterministic; no repository content is sent to a model.
- Scan reliability state is distinct from the severity result.
- Secret evidence is redacted in the rule result itself.
- Operational bounds fail visibly instead of producing an all-clear.
- Examples are synthetic and the package has no runtime dependencies.

## Verification

- Unit and adversarial tests cover state transitions, deterministic order, timeout, file limit, error circuit, exclusions, binary and large files, risky CI, dependency pins, redaction, journal tampering, idempotency, CLI policy, JSON, and SARIF.
- The package is compiled, built, installed into an isolated environment, and exercised through the installed CLI.
- Repository-wide scans check credential-shaped values and prohibited private references before publication.
- Pull-request and post-merge CI are required before tagging a release.

## Limits

Static patterns have false positives and false negatives. The tool does not execute tests, resolve dependency vulnerabilities, prove that a credential is live, analyze full program data flow, sandbox source, or replace expert review. AI-assisted source may contain defects and must be reviewed like any other contribution.

