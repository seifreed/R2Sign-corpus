#!/usr/bin/env python3
"""Measure extraction, scan throughput, memory and storage for scale fixtures."""

import argparse
import hashlib
import json
import platform
from pathlib import Path, PurePosixPath
import resource
import subprocess
import sys
import tempfile
import time
import zipfile

SCHEMA = "r2sign-scale-benchmark/v1"
FIXTURE_SCHEMA = "r2sign-scale-fixtures/v1"
RULE = 'rule r2sign_scale_fixture { strings: $h = "R2SIGN-SAFE-SCALE-FIXTURE" condition: $h at 0 }\n'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--archive", type=Path, default=Path("fixtures/scale-10000.zip")
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path("fixtures/scale-10000-manifest.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--yara", default="yara")
    args = parser.parse_args()
    payload = benchmark(args.archive, args.manifest, args.yara)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


def benchmark(archive: Path, manifest_path: Path, yara: str) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = manifest.get("samples")
    if manifest.get("schema") != FIXTURE_SCHEMA or not isinstance(samples, list):
        raise ValueError("invalid scale fixture manifest")
    if manifest.get("archive_sha256") != _digest(archive):
        raise ValueError("scale fixture archive digest mismatch")
    with tempfile.TemporaryDirectory(prefix="r2sign-scale-") as temporary:
        root = Path(temporary)
        started = time.perf_counter()
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
            expected = [sample["path"] for sample in samples]
            if names != expected or any(not _safe_member(name) for name in names):
                raise ValueError(
                    "scale fixture archive members do not match the manifest"
                )
            bundle.extractall(root)
        extraction_seconds = time.perf_counter() - started
        fixture_root = root / "fixtures"
        files = sorted(path for path in fixture_root.iterdir() if path.is_file())
        if len(files) != manifest.get("sample_count"):
            raise ValueError("extracted scale fixture count mismatch")
        logical_bytes = sum(path.stat().st_size for path in files)
        allocated_bytes = sum(path.stat().st_blocks * 512 for path in files)
        rule = root / "scale.yar"
        rule.write_text(RULE, encoding="ascii")
        started = time.perf_counter()
        scan = subprocess.run(
            [yara, "--recursive", "--count", str(rule), str(fixture_root)],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        scan_seconds = time.perf_counter() - started
        if scan.returncode != 0:
            raise RuntimeError(
                scan.stderr.strip() or f"YARA exited with {scan.returncode}"
            )
        count_lines = scan.stdout.splitlines()
        if len(count_lines) != len(files):
            raise ValueError("YARA did not report one count per fixture")
        try:
            matches = sum(int(line.rsplit(": ", 1)[1]) for line in count_lines)
        except (IndexError, ValueError) as error:
            raise ValueError("unexpected YARA count output") from error
        if matches != len(files):
            raise ValueError(f"YARA matched {matches} fixtures, expected {len(files)}")
        max_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    version = subprocess.run(
        [yara, "--version"], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()
    return {
        "schema": SCHEMA,
        "executed_at": "2026-09-04",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "scanner": f"YARA {version}",
        "archive": str(archive),
        "archive_sha256": _digest(archive),
        "manifest": str(manifest_path),
        "manifest_sha256": _digest(manifest_path),
        "sample_count": len(files),
        "sample_bytes": logical_bytes,
        "matches": matches,
        "extraction_seconds": extraction_seconds,
        "scan_seconds": scan_seconds,
        "files_per_second": len(files) / scan_seconds,
        "bytes_per_second": logical_bytes / scan_seconds,
        "max_rss_bytes": max_rss if sys.platform == "darwin" else max_rss * 1024,
        "storage": {
            "archive_bytes": archive.stat().st_size,
            "manifest_bytes": manifest_path.stat().st_size,
            "extracted_logical_bytes": logical_bytes,
            "extracted_allocated_bytes": allocated_bytes,
        },
    }


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and path.parts[:1] == ("fixtures",)
    )


def _digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
