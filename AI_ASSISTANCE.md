# AI assistance disclosure

## Scope

AI assistance helped draft the architecture, implementation, tests, documentation, and synthetic fixtures for Repo Doctor AI 0.1.0 and 0.2.0. The repository owner selected the scope, approved publication, and remains responsible for releases and maintenance.

## Human-controlled decisions

- The scanner is offline and deterministic; no repository content is sent to a model.
- Scan reliability state is distinct from the severity result.
- Secret evidence is redacted in the rule result and through a shared final sanitizer for every output artifact.
- Operational bounds fail visibly instead of producing an all-clear.
- Examples are synthetic and the package has no runtime dependencies.

## Verification

- Unit and adversarial tests cover state transitions, deterministic order, all resource limits, ancestor-symlink races, multi-ecosystem manifests, risky CI, global redaction, terminal/SARIF safety, plugin deadlines and identities, scoring, expiring baselines, exact regression diffs, plans, all report formats, SBOM rejection, journal tampering, idempotency, and CLI alias policy.
- Both wheel and source distribution are compiled, rebuilt, installed into isolated environments, and exercised through the installed CLI.
- Repository-wide scans check credential-shaped values and prohibited private references before publication.
- Pull-request and post-merge CI are required before tagging a release.

## Limits

Static patterns have false positives and false negatives. The tool does not execute tests, resolve dependency vulnerabilities, prove that a credential is live, analyze full program data flow, sandbox source, or replace expert review. AI-assisted source may contain defects and must be reviewed like any other contribution.
