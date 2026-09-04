# R2Sign public corpus

This repository contains an auditable, stratified corpus for reproducible
R2Sign signature benchmarks. Samples are PE files and must be handled in an
isolated analysis environment. Do not execute samples on a production host.

The corpus is distributed under the terms that apply to the source samples.
The repository metadata is MIT licensed. See [PROVENANCE.md](docs/PROVENANCE.md)
for source licenses, attribution, selection rules, and mutation provenance.

## Layout

- `expanded/training/`: stratified training samples from seven labelled families.
- `expanded/holdout/`: family-matched holdout samples excluded from construction.
- `near_family/`: samples from related but distinct families.
- `mutations/`: deterministic byte-level derivatives of training samples.
- `goodware/`: benign PE samples used for false-positive checks.
- `manifest.json`: SHA-256 protected `r2sign-corpus/v1` manifest.
- `metadata/provenance-evidence.json`: source timestamps and builder fingerprints.
- `metadata/a1000-corpus.json`: non-redistributable A1000 sample index.
- `benchmark/`: fixed benchmark inputs and thresholds.
- `rules/`: generated rules used by the benchmark.
- `goodware-r2sign.zip`: downloadable goodware database bundle with checksums.
- `comparison/`: reproducible VxSig/BinDiff comparison artifacts on this corpus.

Version `0.5.0` contains 1,410 verified samples: 440 labelled malware samples,
966 goodware samples, two near-family samples, and two deterministic
mutations. The malware split covers seven labelled families selected from the
published VirusTotal labels: Cabby, FakeAV, Kryptik, Mediyes, Sirefef, Upatre
and Zbot. Its aggregate size exceeds the approximately 95% confidence,
plus-or-minus 5% finite-population target for the 8878-sample labelled PE
population. Family quotas preserve rare families, so the split is calibrated
for aggregate detection evaluation rather than a family-prevalence estimate.
Every sample is identified by SHA-256 and ssdeep, and linked to its public
source record. Label confidence is derived from the pinned DikeDataset malice
score and recorded with its source evidence in `metadata/label-evidence.json`.
Runtime metadata is extracted with `rabin2 -Ij` and retained in
`metadata/runtime-evidence.json`. The 307 training samples come from the two
earlier source commits; all 133 holdout samples come from the later commit.
`metadata/provenance-evidence.json` records the source commit timestamp and an
opaque Rich Header or binary-header builder fingerprint for every sample.

## Verification

Run the standalone integrity checks from this repository:

```bash
tools/verify-corpus
```

This verifies the manifest structure and uniqueness, every sample SHA-256,
the provider audit partitions, the goodware database digest, and all 10,000
scale fixtures. The R2Sign release-contract check additionally validates the
redistribution and temporal-separation metadata:

```bash
PYTHONPATH=../R2Sign/src python3.14 -m r2sign.cli.app corpus manifest.json
```

Materialize the licensed, non-derived samples through an authenticated
VirusTotal CLI without placing the downloaded staging directory in Git:

```bash
tools/vt-materialize manifest.json .vt-materialized \
  metadata/vt-materialization.json
```

The command accepts only a manifest marked as redistributable, sends declared
SHA-256 values to `vt download`, verifies every downloaded digest, and writes a
hash-only audit. Mutation samples remain reproducible from their documented
source sample and are not requested from VirusTotal. Interrupted or
quota-limited runs are resumable: subsequent executions request only missing
or invalid files and refresh the audit with verified and pending hashes.
Use `--audit-only` as the final argument to refresh the partial report without
consuming VirusTotal quota.

The same licensed hashes can be materialized through an authenticated
ReversingLabs A1000 profile when VirusTotal quota is unavailable:

```bash
tools/rl-materialize manifest.json .rl-materialized \
  metadata/rl-materialization.json
```

The command searches pending hashes in batches, downloads only samples marked
available by A1000, verifies each SHA-256, and records a resumable hash-only
audit. Files not present in A1000 remain listed as missing.

`metadata/a1000-corpus.json` adds 1,000 available malicious PE records from 96
families for analysts with access to the configured A1000 instance. Materialize
and verify them locally with:

```bash
tools/rl-materialize metadata/a1000-corpus.json .rl-materialized/a1000 \
  metadata/a1000-materialization.json
```

The index contains hashes and analysis metadata only. The downloaded binaries
remain ignored because A1000 access does not grant this repository permission
to redistribute them.

Run the benchmark and write its JSON result with:

```bash
PYTHONPATH=../R2Sign/src python3.14 -m r2sign.cli.app benchmark benchmark/manifest.yml \
  > benchmark/results.json
```

The benchmark requires YARA-X when the optional dependency is installed and
fails when any declared threshold is missed.
The fixed release smoke cohort contains two FakeAV training samples sharing
builder `rich:e298e226a220a277` and two later holdout samples from the same
builder. It is measured against all 966 goodware samples and both near-family
samples. The broader multi-family results are published separately below.

Package and verify the complete release artifact set with:

```bash
PYTHONPATH=../R2Sign/src python3.14 -m r2sign.cli.app corpus manifest.json \
  --package --output corpus-r2sign.zip
PYTHONPATH=../R2Sign/src python3.14 -m r2sign.cli.app release-check \
  corpus-r2sign.zip benchmark/results.json goodware-r2sign.zip \
  comparison/representative/comparison.json \
  --commit-sha 1edb364d2f706200f06bee9aeeb5f57ef30ae773 > release-check.json
```

`release-check.json` records the passing gate. The 176 MB corpus ZIP remains
ignored and is intended for release-asset storage rather than Git.

## Goodware distribution

`goodware-r2sign.zip` contains the SQLite pattern database, its
`r2sign-goodware/v1` manifest, and `SHA256SUMS`. The database contains three
benign PE samples from the public source dataset plus five synthetic fixtures
covering ELF, Mach-O and PE on x86, x86-64 and ARM64. Verify it with:

```bash
PYTHONPATH=../R2Sign/src python3.14 -m r2sign.cli.app goodware verify goodware-db/manifest.json
PYTHONPATH=../R2Sign/src python3.14 -m r2sign.cli.app goodware package goodware-db/manifest.json \
  --output /tmp/goodware-r2sign.zip
```

The published bundle SHA-256 is recorded in the release asset and the bundle's
`SHA256SUMS` file.
Redistribution remains subject to the source dataset license and attribution
requirements documented in [PROVENANCE.md](docs/PROVENANCE.md).

## Synthetic scale fixtures

`fixtures/scale-10000.zip` contains 10,000 deterministic, non-executable
512-byte fixtures for scan-throughput and storage tests. They do not represent
goodware diversity and must not be used to support false-positive claims.
Rebuild or verify the archive with:

```bash
python3.14 tools/build_scale_fixtures.py
python3.14 tools/build_scale_fixtures.py --verify
python3.14 tools/benchmark_scale_fixtures.py \
  --output fixtures/scale-10000-benchmark.json
```

`fixtures/scale-10000-benchmark.json` publishes the measured extraction time,
scan time, throughput, peak resident memory, and logical and allocated storage.

## External comparison

`comparison/representative/` publishes one common measurement of BASS, VxSig,
yarGen-Go and yara-signator. Generation used 21 training samples across seven
families. Evaluation used all 133 temporal holdout samples, all 966 goodware
samples, both near-family samples, both mutations, and 100 non-redistributable
A1000 samples from 47 other families. The private sample index contains hashes
and metadata only.

`comparison/representative/comparison.json` is the normalized four-tool matrix
accepted by the release gate. The directory retains every generated signature,
raw metric file, external benchmark wrapper, tool commit and artifact digest.
Its R2Sign baseline uses the same 21-sample, seven-family training cohort and
the same evaluation sets as every external tool.
BASS used the published IDA Pro 9.3 adapter and BinDiff 8 workflow; no legacy
IDA 7 Docker result is claimed. See `comparison/representative/README.md` for
the measured table and generation outcomes by family.

`comparison/bass-algorithm-benchmark.json` separately records execution of
BASS's published `hamming_klcs_c` component over the same 32 recompilations used
for the R2Sign matcher validation. It produced a 67-byte common sequence with
32/32 subsequence recall. This is explicitly an algorithm-component comparison,
not a substitute for the unavailable IDA/BinExport pipeline.

`comparison/recompilation-benchmark.json` records a local scale validation of
the progressive alignment matcher over 32 independently compiled variants of
the benign `recompilation_fixture.c` source. The report includes the compiler,
radare2, source digest, selected pattern, and complete `32/32` recall. Binaries
are intentionally not distributed; they are regenerated from the committed
fixture.

The artifact SHA-256 is recorded in both JSON documents.
