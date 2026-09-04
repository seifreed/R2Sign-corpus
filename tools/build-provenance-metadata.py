#!/usr/bin/env python3
"""Build source and PE builder evidence for the redistributable corpus."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any
from urllib.parse import urlparse

SOURCE_SNAPSHOT = "5200762e5db1d33b77a125a6964fed49b3c2dd2d"
HEADER_FIELDS = (
    "Machine",
    "Characteristics",
    "Magic",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "Subsystem",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=Path("manifest.json"))
    parser.add_argument(
        "--evidence", type=Path, default=Path("metadata/provenance-evidence.json")
    )
    parser.add_argument("--rabin2", default="rabin2")
    args = parser.parse_args()
    build(args.manifest, args.evidence, args.source_repository, args.rabin2)
    return 0


def build(
    manifest_path: Path, evidence_path: Path, source_repository: Path, rabin2: str
) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    history = _source_history(source_repository)
    samples = manifest["samples"]
    source_records = [_source_record(sample, history) for sample in samples]
    malware_times = sorted(
        {
            record["first_seen"]
            for sample, record in zip(samples, source_records, strict=True)
            if sample["role"] in {"training", "holdout"}
        }
    )
    if len(malware_times) < 2:
        raise ValueError("malware source history does not contain a temporal split")
    holdout_time = malware_times[-1]

    evidence_samples: list[dict[str, Any]] = []
    for sample, source in zip(samples, source_records, strict=True):
        if sample["role"] in {"training", "holdout"}:
            role = "holdout" if source["first_seen"] == holdout_time else "training"
            _move_for_role(sample, role)
            sample["role"] = role
        if sample["role"] == "mutation":
            source["first_seen"] = _first_repository_commit(Path(sample["path"]))[1]
            version = f"append-v1@{source['source_commit']}"
        else:
            version = f"dike@{source['source_commit']}"
        builder, builder_evidence = _builder(Path(sample["path"]), rabin2)
        sample["first_seen"] = source["first_seen"]
        sample["sample_version"] = version
        sample["builder"] = builder
        evidence_samples.append(
            {
                "sha256": sample["sha256"],
                "source_path": source["source_path"],
                "source_commit": source["source_commit"],
                "first_seen": source["first_seen"],
                "sample_version": version,
                "builder": builder,
                "builder_evidence": builder_evidence,
            }
        )

    _validate_split(samples)
    manifest["version"] = "0.5.0"
    manifest["provenance"] = [
        f"https://github.com/iosifache/DikeDataset/tree/{SOURCE_SNAPSHOT}",
        "https://figshare.com/articles/dataset/Malware_Detection_PE-Based_Analysis_Using_Deep_Learning_Algorithm_Dataset/6635642",
        "DikeDataset PE source is documented as CC BY 4.0",
        "first_seen is the timezone-aware timestamp of first inclusion in the source Git history",
        "training contains the two earlier malware source batches; holdout contains the latest batch",
        "builder is an opaque fingerprint of observed Rich Header or PE header evidence",
        "Mutations are generated deterministically from the declared training samples",
    ]
    _write_json(manifest_path, manifest)
    evidence = {
        "schema": "r2sign-provenance-evidence/v1",
        "source_repository": "https://github.com/iosifache/DikeDataset",
        "source_snapshot": SOURCE_SNAPSHOT,
        "first_seen_method": "first Git commit adding the source path",
        "builder_extractor": {
            "command": f"{rabin2} -HHj",
            "version": _run([rabin2, "-v"]).splitlines()[0],
        },
        "samples": evidence_samples,
    }
    _write_json(evidence_path, evidence)


def _source_history(repository: Path) -> dict[str, tuple[str, str]]:
    output = _run(
        [
            "git",
            "-C",
            str(repository),
            "log",
            "--all",
            "--reverse",
            "--diff-filter=A",
            "--format=@%H%x09%cI",
            "--name-only",
            "--",
            "files/benign",
            "files/malware",
        ]
    )
    history: dict[str, tuple[str, str]] = {}
    commit = ""
    timestamp = ""
    for line in output.splitlines():
        if line.startswith("@"):
            commit, timestamp = line[1:].split("\t", maxsplit=1)
        elif line and line not in history:
            history[line] = (commit, timestamp)
    return history


def _source_record(
    sample: dict[str, Any], history: dict[str, tuple[str, str]]
) -> dict[str, str]:
    url_path = urlparse(sample["source_url"]).path
    marker = f"/{SOURCE_SNAPSHOT}/"
    if marker not in url_path:
        raise ValueError(f"source URL is not pinned to {SOURCE_SNAPSHOT}")
    source_path = url_path.split(marker, maxsplit=1)[1]
    if source_path not in history:
        raise ValueError(f"source path is absent from Git history: {source_path}")
    commit, first_seen = history[source_path]
    return {
        "source_path": source_path,
        "source_commit": commit,
        "first_seen": first_seen,
    }


def _first_repository_commit(path: Path) -> tuple[str, str]:
    output = _run(
        [
            "git",
            "log",
            "--reverse",
            "--diff-filter=A",
            "--format=%H%x09%cI",
            "--",
            str(path),
        ]
    )
    line = next((item for item in output.splitlines() if item), "")
    if not line:
        raise ValueError(f"path has no repository introduction commit: {path}")
    commit, timestamp = line.split("\t", maxsplit=1)
    return commit, timestamp


def _builder(path: Path, rabin2: str) -> tuple[str, dict[str, Any]]:
    fields = json.loads(_run([rabin2, "-HHj", str(path)]))["fields"]
    rich_entries: list[dict[str, Any]] = []
    for field in fields:
        name = field.get("name")
        if name == "RICH_ENTRY_NAME":
            rich_entries.append({"product": field.get("comment", "unknown")})
        elif rich_entries and name in {
            "RICH_ENTRY_ID",
            "RICH_ENTRY_VERSION",
            "RICH_ENTRY_TIMES",
        }:
            rich_entries[-1][name.removeprefix("RICH_ENTRY_").lower()] = field.get(
                "value", 0
            )
    if rich_entries:
        return _fingerprint("rich", {"entries": rich_entries})
    header = {
        field["name"]: field.get("value", 0)
        for field in fields
        if field.get("name") in HEADER_FIELDS
    }
    if header:
        return _fingerprint("pe-header", {"fields": header})
    with path.open("rb") as sample_file:
        prefix = sample_file.read(4096)
    return _fingerprint(
        "binary-prefix",
        {
            "bytes_hashed": len(prefix),
            "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
        },
    )


def _fingerprint(kind: str, evidence: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    return f"{kind}:{digest[:16]}", {
        "kind": kind,
        "fingerprint_sha256": digest,
    }


def _move_for_role(sample: dict[str, Any], role: str) -> None:
    old_path = Path(sample["path"])
    new_path = Path("expanded", role, sample["family"], old_path.name)
    if old_path == new_path:
        return
    if new_path.exists() and not old_path.exists():
        sample["path"] = str(new_path)
        return
    new_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.rename(new_path)
    sample["path"] = str(new_path)


def _validate_split(samples: list[dict[str, Any]]) -> None:
    training = [sample for sample in samples if sample["role"] == "training"]
    holdout = [sample for sample in samples if sample["role"] == "holdout"]
    for family in {sample["family"] for sample in training + holdout}:
        family_training = [sample for sample in training if sample["family"] == family]
        family_holdout = [sample for sample in holdout if sample["family"] == family]
        if not family_training or not family_holdout:
            raise ValueError(f"temporal split is incomplete for {family}")
        if min(sample["first_seen"] for sample in family_holdout) <= max(
            sample["first_seen"] for sample in family_training
        ):
            raise ValueError(f"holdout is not newer than training for {family}")


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _run(command: list[str]) -> str:
    return subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=300
    ).stdout


if __name__ == "__main__":
    raise SystemExit(main())
