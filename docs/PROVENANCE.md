# Provenance and redistribution

## Source dataset

The PE samples in this seed corpus were selected from
[DikeDataset](https://github.com/iosifache/DikeDataset) at commit
`5200762e5db1d33b77a125a6964fed49b3c2dd2d`. DikeDataset documents the PE
source as the
[Malware Detection PE-Based Analysis Using Deep Learning Algorithm Dataset](https://figshare.com/articles/dataset/Malware_Detection_PE-Based_Analysis_Using_Deep_Learning_Algorithm_Dataset/6635642)
and identifies that source as `CC BY 4.0`.

The source dataset metadata identifies malicious samples with VirusTotal
labels. The family labels in this repository use the dominant family names
present in the published tags: `Mediyes`, `Kryptik`, and `Cabby`.

## Selection

- `training/mediyes/` contains three distinct Mediyes samples.
- `holdout/mediyes/` contains two distinct Mediyes samples excluded from rule construction.
- `near_family/` contains one Kryptik and one Cabby sample.
- `goodware/pe/` contains three benign PE samples from the same published source dataset.
- `mutations/mediyes/` contains deterministic derivatives of two training samples.

The original samples retain their published SHA-256 identifiers in their
filenames. The manifest records the digest of every stored file, including
mutations.

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
