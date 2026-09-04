# Representative external comparison

This directory records a 2026-09-04 execution of BASS, VxSig, yarGen-Go and
yara-signator against one shared corpus contract.

Generation used three training samples from the largest `builder` cohort of
each of the seven public families. Measurement used those 21 samples, all 133
later holdout samples, all 966 public goodware samples, both near-family
samples, both mutations, and 100 non-redistributable A1000 samples from 47
other named families. `evidence.json` lists every public training input,
artifact digest, tool commit and metric. `cross-family-a1000.json` lists the
private sample hashes and metadata without redistributing their bytes.

| Tool | Rules/families | Training | Holdout | Goodware FP | Cross-family | Scan seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BASS | 2/7 | 2/21 | 0/133 | 0/966 | 0/100 | 35.218 |
| VxSig | 6/7 | 11/21 | 32/133 | 62/966 | 18/100 | 3.882 |
| yara-signator | 6/7 | 18/21 | 50/133 | 0/966 | 0/100 | 3.314 |
| yarGen-Go | 7/7 | 21/21 | 66/133 | 663/966 | 40/100 | 3.499 |

The table includes failed generation outcomes instead of dropping those
families. BASS and VxSig consumed IDA Pro 9.3/BinDiff 8 artifacts. BASS used
the `ida93-python3` fork. yara-signator consumed SMDA 4.5.0 reports and ran its
PostgreSQL/capstone_server pipeline. yarGen-Go used a goodware database built
from the same 966 public goodware samples and ran without LLM assistance.

The four `*-metrics.json` files are raw `BenchmarkResult` records emitted by
R2Sign's common scanner. YARA artifacts were compiled by both YARA and YARA-X;
the BASS NDB was scanned by ClamAV.
