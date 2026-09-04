#!/usr/bin/env python3
"""Build deterministic, non-executable fixtures for scan-scale validation."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

SCHEMA = "r2sign-scale-fixtures/v1"
SEED = b"R2Sign safe scale fixture v1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--archive", type=Path, default=Path("fixtures/scale-10000.zip")
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path("fixtures/scale-10000-manifest.json")
    )
    parser.add_argument("--count", type=int, default=10_000)
    parser.add_argument("--size", type=int, default=512)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify(args.archive, args.manifest)
        return 0
    if args.count < 1 or args.size < 64:
        parser.error("--count must be positive and --size must be at least 64")
    build(args.archive, args.manifest, args.count, args.size)
    verify(args.archive, args.manifest)
    return 0


def build(archive: Path, manifest_path: Path, count: int, size: int) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_archive = archive.with_name(f"{archive.name}.tmp")
    samples: list[dict[str, object]] = []
    with zipfile.ZipFile(
        temporary_archive, "w", compression=zipfile.ZIP_STORED
    ) as bundle:
        for index in range(count):
            name = f"fixtures/{index:05d}.bin"
            data = _fixture(index, size)
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            bundle.writestr(info, data)
            samples.append(
                {
                    "path": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    temporary_archive.replace(archive)
    manifest = {
        "schema": SCHEMA,
        "version": "1.0.0",
        "license": "MIT",
        "purpose": "scan throughput and storage scale only",
        "sample_count": count,
        "sample_size": size,
        "archive": archive.name,
        "archive_sha256": _sha256(archive),
        "samples": samples,
    }
    temporary_manifest = manifest_path.with_name(f"{manifest_path.name}.tmp")
    temporary_manifest.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    temporary_manifest.replace(manifest_path)


def verify(archive: Path, manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA or manifest.get("archive_sha256") != _sha256(
        archive
    ):
        raise ValueError("scale fixture manifest does not match archive")
    samples = manifest.get("samples")
    if not isinstance(samples, list) or manifest.get("sample_count") != len(samples):
        raise ValueError("scale fixture sample count is invalid")
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != [sample["path"] for sample in samples]:
            raise ValueError("scale fixture archive members do not match manifest")
        for sample in samples:
            data = bundle.read(sample["path"])
            if (
                len(data) != sample["size"]
                or hashlib.sha256(data).hexdigest() != sample["sha256"]
            ):
                raise ValueError(f"scale fixture mismatch: {sample['path']}")
    print(f"scale fixtures: ok ({len(samples)} samples)")


def _fixture(index: int, size: int) -> bytes:
    header = b"R2SIGN-SAFE-SCALE-FIXTURE\0" + index.to_bytes(8, "big")
    return header + hashlib.shake_256(SEED + index.to_bytes(8, "big")).digest(
        size - len(header)
    )


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
