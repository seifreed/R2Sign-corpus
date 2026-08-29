# R2Sign public corpus

This repository contains a small, auditable seed corpus for reproducible
R2Sign signature benchmarks. Samples are PE files and must be handled in an
isolated analysis environment. Do not execute samples on a production host.

The corpus is distributed under the terms that apply to the source samples.
The repository metadata is MIT licensed. See [PROVENANCE.md](docs/PROVENANCE.md)
for source licenses, attribution, selection rules, and mutation provenance.

## Layout

- `training/`: samples used to derive a detection rule.
- `holdout/`: same-family samples excluded from rule construction.
- `near_family/`: samples from related but distinct families.
- `mutations/`: deterministic byte-level derivatives of training samples.
- `goodware/`: benign PE samples used for false-positive checks.
- `manifest.json`: SHA-256 protected `r2sign-corpus/v1` manifest.
- `benchmark/`: fixed benchmark inputs and thresholds.
- `rules/`: generated rules used by the benchmark.

The current version is a seed corpus, not a prevalence estimate. Every sample
is identified by SHA-256 and linked to its public source record.

## Verification

From the R2Sign repository:

```bash
PYTHONPATH=../R2Sign python -m r2sign.cli.app corpus manifest.json
```

The command verifies the manifest and every sample digest.

Run the benchmark and write its JSON result with:

```bash
PYTHONPATH=../R2Sign python -m r2sign.cli.app benchmark benchmark/manifest.yml \
  > benchmark/results.json
```

The benchmark requires YARA-X when the optional dependency is installed and
fails when any declared threshold is missed.
