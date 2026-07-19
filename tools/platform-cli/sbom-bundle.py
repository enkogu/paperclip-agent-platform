#!/usr/bin/env python3
"""Validate and assemble the complete release SBOM set deterministically."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import re
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_entries(
    root: Path, release_sha: str, repository: str
) -> dict[str, dict[str, str]]:
    targets = load_module(root / "tools/platform-cli/sbom-targets.py", "sbom_targets")
    entries = {
        f"paperclip-agent-platform-source-{release_sha}.spdx.json": {
            "kind": "source",
            "repository": repository,
            "commit": release_sha,
        }
    }
    for target in targets.release_images(root):
        entries[
            f"paperclip-agent-platform-image-{target['id']}-{release_sha}.spdx.json"
        ] = {"kind": "image", **target}
    return entries


def validate_inputs(
    directory: Path, root: Path, release_sha: str, repository: str
) -> tuple[dict[str, dict[str, str]], dict[str, bytes]]:
    if FULL_SHA.fullmatch(release_sha) is None:
        raise ValueError("release SHA must be a full lowercase commit SHA")
    expected = expected_entries(root, release_sha, repository)
    actual = {path.name for path in directory.glob("*.spdx.json") if path.is_file()}
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        extra = sorted(actual - set(expected))
        raise ValueError(
            f"SBOM set is incomplete or unexpected: missing={missing} extra={extra}"
        )

    verifier = load_module(root / "tools/platform-cli/verify-sbom.py", "verify_sbom")
    payloads: dict[str, bytes] = {}
    for name, identity in sorted(expected.items()):
        path = directory / name
        if identity["kind"] == "source":
            findings = verifier.verify(
                path,
                expected_target=release_sha,
                expected_root_name=repository,
                expected_root_version=release_sha,
            )
        else:
            findings = verifier.verify(
                path,
                expected_target=release_sha,
                expected_root_name=identity["root_name"],
                expected_root_version=identity["root_version"],
                expected_root_purl=identity["purl"],
                expected_digest=identity["digest"],
            )
        if findings:
            raise ValueError(f"{name}: {'; '.join(findings)}")
        payloads[name] = path.read_bytes()
    return expected, payloads


def tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def build_bundle(
    directory: Path,
    output: Path,
    *,
    root: Path,
    release_sha: str,
    repository: str,
) -> dict[str, Any]:
    expected, payloads = validate_inputs(directory, root, release_sha, repository)
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "PaperclipReleaseSbomBundle",
        "repository": repository,
        "commit": release_sha,
        "files": [
            {
                "path": f"sbom/{name}",
                "sha256": sha256(payloads[name]),
                **expected[name],
            }
            for name in sorted(expected)
        ],
    }
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
            ) as archive:
                archive.addfile(
                    tar_info("manifest.json", len(manifest_bytes)),
                    io.BytesIO(manifest_bytes),
                )
                for name, data in sorted(payloads.items()):
                    archive.addfile(
                        tar_info(f"sbom/{name}", len(data)), io.BytesIO(data)
                    )
    return manifest


def verify_bundle(path: Path) -> dict[str, Any]:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if any(not member.isfile() for member in members):
            raise ValueError("bundle may contain files only")
        if not members or members[0].name != "manifest.json":
            raise ValueError("bundle manifest is absent or not first")
        manifest_file = archive.extractfile(members[0])
        if manifest_file is None:
            raise ValueError("bundle manifest is unreadable")
        manifest = json.loads(manifest_file.read())
        expected = {row["path"]: row["sha256"] for row in manifest.get("files") or []}
        actual_names = {member.name for member in members[1:]}
        if actual_names != set(expected):
            raise ValueError("bundle member set does not match its manifest")
        for member in members[1:]:
            extracted = archive.extractfile(member)
            if extracted is None or sha256(extracted.read()) != expected[member.name]:
                raise ValueError(f"bundle checksum mismatch: {member.name}")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--release-sha")
    parser.add_argument("--repository")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            manifest = verify_bundle(args.verify)
        else:
            if not all(
                (args.directory, args.output, args.release_sha, args.repository)
            ):
                parser.error(
                    "build mode requires directory, output, release-sha and repository"
                )
            manifest = build_bundle(
                args.directory,
                args.output,
                root=args.root.resolve(),
                release_sha=args.release_sha,
                repository=args.repository,
            )
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"sbom-bundle: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
