# Contributing

1. Open an issue describing the false positive, false negative, or reliability invariant.
2. Add a synthetic counter-example that fails before the change.
3. Keep findings stable: code and fingerprint inputs are public compatibility surfaces.
4. For a rule plugin, prove deterministic order, bounded evidence, redaction, invalid input, and finding-limit behavior.
5. Run unit tests, compilation, wheel and sdist build/install, self-audit, synthetic demo, report renderers, and SBOM generation.
6. Update the specification and changelog when behavior changes.

Never commit live credentials, customer data, private source, or internal infrastructure details. Security fixtures must be assembled from clearly fake fragments so repository-wide scanners do not mistake them for usable values.
