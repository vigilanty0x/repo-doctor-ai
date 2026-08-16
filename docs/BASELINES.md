# Baseline governance

A baseline records reviewed debt; it does not prove a finding is harmless. Baselines are deterministic JSON documents with a source-report hash and one entry per finding fingerprint.

Every entry contains:

- the exact finding fingerprint;
- the stable diagnostic code;
- a reason between 8 and 500 characters;
- an optional ISO date after which suppression stops.

Use a reason that names the compensating control or tracked migration. Prefer short expiries for high-severity debt. Commit the baseline only after code-owner review. A scan preserves matched entries in `suppressed_findings` and publishes both active and raw scores.

Expired, unknown, code-mismatched, and malformed entries never suppress findings. Duplicate fingerprints and duplicate JSON keys reject the complete baseline. Deleting a baseline immediately restores all matching findings on the next scan.

Recommended pull-request gate:

```bash
repo-doctor scan . --baseline repo-doctor-baseline.json --format json --output candidate.json --fail-on high
repo-doctor diff main.json candidate.json --fail-on-regression
```

Review the baseline periodically even when no regression occurs. Stable debt can still become unacceptable as threat models, ownership, or runtime exposure change.
