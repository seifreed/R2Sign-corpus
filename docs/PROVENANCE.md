# Provenance and redistribution

## Source dataset

The PE samples in this corpus were selected from
[DikeDataset](https://github.com/iosifache/DikeDataset) at commit
`5200762e5db1d33b77a125a6964fed49b3c2dd2d`. DikeDataset documents the PE
source as the
[Malware Detection PE-Based Analysis Using Deep Learning Algorithm Dataset](https://figshare.com/articles/dataset/Malware_Detection_PE-Based_Analysis_Using_Deep_Learning_Algorithm_Dataset/6635642)
and identifies that source as `CC BY 4.0`.

The source dataset metadata identifies malicious samples with VirusTotal
labels. The expanded split uses the first matching family in this fixed
priority order when a published tag contains more than one family name:
`Mediyes`, `Cabby`, `Sirefef`, `Upatre`, `Kryptik`, `Zbot`, `FakeAV`.
Selection is deterministic and limited to PE files whose source path and
SHA-256 agree. The source population contains 8878 valid labelled PE
candidates after that priority assignment. The initial malware split uses
predeclared family quotas totalling 447 samples, with complete retention of
families below the quota floor. Exact ssdeep duplicates are reduced to one
representative, removing seven redundant samples. The holdout representative
is retained when a duplicate group crosses splits; otherwise a VT-verified
member with the smallest SHA-256 is retained. Within each family, candidates
are ordered by
the SHA-256 digest of `R2Sign-corpus-v3:<family>:<sample hash>`; every fifth
selected sample is holdout. This exceeds the approximately 95% confidence,
plus-or-minus 5% aggregate finite-population target. Family quotas preserve
rare families, so the split is calibrated for aggregate detection evaluation
and does not claim to represent family prevalence.

## Selection

- `training/mediyes/` contains three distinct Mediyes samples.
- `holdout/mediyes/` contains two distinct Mediyes samples excluded from rule construction.
- `expanded/training/<family>/` contains 342 samples across seven labelled
  families.
- `expanded/holdout/<family>/` contains 98 samples across the same families,
  excluded from rule construction.
- `near_family/` contains one Kryptik and one Cabby sample.
- `goodware/pe/` contains 966 benign PE samples from the same published source dataset.
- `goodware/fixtures/` contains five synthetic MIT-licensed fixtures covering ELF, Mach-O and PE on x86, x86-64 and ARM64. They were compiled locally and never executed.
- `mutations/mediyes/` contains deterministic derivatives of two training samples.

The original samples retain their published SHA-256 identifiers in their
filenames. The manifest records the digest of every stored file, including
mutations.

## Label confidence

`metadata/label-evidence.json` retains the DikeDataset malice score for every
source sample. Malware confidence uses that score directly; benign confidence
uses `1 - malice_score`. Scores at or above `0.8` are high, scores at or above
`0.5` are medium, and lower scores are low. Deterministic mutations inherit
the label evidence of their declared source sample.

## Mutations

Each mutation is made by appending the fixed ASCII marker `R2SIGN-MUTATION-V1`
with a deterministic four-byte prefix. No sample is executed or otherwise
modified. The mutation source is the corresponding training sample identified
by the `source_url` field in `manifest.json`.

## License

The repository metadata is MIT licensed. Source sample files remain subject to
the source dataset's `CC BY 4.0` terms and required attribution. This
repository does not relicense third-party sample content. Redistribution must
retain this file, the manifest, and the source attribution.

## Safety

Samples are provided for malware-analysis research. Use an isolated host,
restrict network access, and follow the policies of the source dataset and
your organization. The corpus contains no credentials or analyst-local paths.
