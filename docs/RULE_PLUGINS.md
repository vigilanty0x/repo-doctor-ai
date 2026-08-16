# Trusted rule plugins

`RuleRegistry` is a composable in-process API. A plugin declares a stable name, category, description, and callable. The callable receives the bounded `SourceFile` inventory and returns `Finding` objects.

Plugin requirements:

- names and categories use a safe lowercase identifier;
- names are unique;
- findings use the plugin category;
- severities are `info`, `low`, `medium`, `high`, or `critical`;
- classifications are `proof`, `inference`, or `blockage`;
- evidence must be bounded and must not contain credentials or private values;
- output must be deterministic for the same inventory;
- exact duplicate findings are collapsed, while the same fingerprint with conflicting fields is rejected;
- plugins must honor the scan deadline and must not suppress `BaseException`/timeout signals; file iteration and result collection check the deadline automatically;
- the callable must not execute target code, use the network, or mutate the repository.

The registry validates result type, category, severity, and classification. Plugins execute in stable name order and share the configured global finding bound. A violation raises `RegistryError`; it is never converted into a successful scan.

Applications explicitly construct and pass a registry to `Scanner`. The CLI intentionally has no dynamic plugin-discovery flag because importing modules named by an untrusted repository would violate the scanner boundary.

Test a plugin through `Scanner.scan`, including absent/present fixtures, invalid input, final evidence redaction, deterministic ordering, duplicate identity, deadline, and finding-limit behavior. Treat diagnostic code and fingerprint inputs as public compatibility surfaces.
