# R2Sign public corpus

This repository contains an auditable, stratified corpus for reproducible
R2Sign signature benchmarks. Samples are PE files and must be handled in an
isolated analysis environment. Do not execute samples on a production host.

The corpus is distributed under the terms that apply to the source samples.
The repository metadata is MIT licensed. See [PROVENANCE.md](docs/PROVENANCE.md)
for source licenses, attribution, selection rules, and mutation provenance.

## Layout

- `training/`: samples used to derive a detection rule.
- `holdout/`: same-family samples excluded from rule construction.
- `expanded/training/`: stratified training samples from seven labelled families.
- `expanded/holdout/`: family-matched holdout samples excluded from construction.
- `near_family/`: samples from related but distinct families.
- `mutations/`: deterministic byte-level derivatives of training samples.
- `goodware/`: benign PE samples used for false-positive checks.
- `manifest.json`: SHA-256 protected `r2sign-corpus/v1` manifest.
- `benchmark/`: fixed benchmark inputs and thresholds.
- `rules/`: generated rules used by the benchmark.
- `goodware-r2sign.zip`: downloadable goodware database bundle with checksums.
- `comparison/`: reproducible VxSig/BinDiff comparison artifacts on this corpus.

Version `0.2.0` contains 136 verified samples. The expanded split contains
seven labelled families selected deterministically from the published
VirusTotal labels: Cabby, FakeAV, Kryptik, Mediyes, Sirefef, Upatre and Zbot.
It is a stratified detection benchmark, not a prevalence estimate. Every
sample is identified by SHA-256 and linked to its public source record.

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

## Goodware distribution

`goodware-r2sign.zip` contains the SQLite pattern database, its
`r2sign-goodware/v1` manifest, and `SHA256SUMS`. The database contains three
benign PE samples from the public source dataset plus five synthetic fixtures
covering ELF, Mach-O and PE on x86, x86-64 and ARM64. Verify it with:

```bash
PYTHONPATH=../R2Sign python -m r2sign.cli.app goodware verify goodware-db/manifest.json
PYTHONPATH=../R2Sign python -m r2sign.cli.app goodware package goodware-db/manifest.json \
  --output /tmp/goodware-r2sign.zip
```

The published bundle SHA-256 is recorded in the release asset and the bundle's
`SHA256SUMS` file.
Redistribution remains subject to the source dataset license and attribution
requirements documented in [PROVENANCE.md](docs/PROVENANCE.md).

## External comparison

`comparison/comparison.json` records the metric deltas against VxSig built from
commit `5afa34b60656624e125e8555dc48b04e3ae8ef04`. The directory also contains
the generated VxSig rule, its benchmark manifest and JSON, and the real BinDiff
v8 artifact created from Ghidra `BinExport` files for one training and one
holdout sample. Reproduce the external benchmark with:

```bash
PYTHONPATH=../R2Sign python -m r2sign.cli.app benchmark \
  comparison/vxsig-benchmark.yml > /tmp/vxsig-benchmark.json
```

The artifact SHA-256 is recorded in both JSON documents.
