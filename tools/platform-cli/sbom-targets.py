#!/usr/bin/env python3
"""Emit the immutable image matrix covered by the release SBOM workflow."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = Path("config/dependencies.lock.json")
IMAGE_REF = re.compile(r"^[^\s@]+(?::[^\s@]+)?@sha256:[0-9a-f]{64}$")
PLATFORM_IMAGE = re.compile(r"^    ([A-Za-z][A-Za-z0-9]*):\s+(\S+)\s*$")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def platform_lock_images(path: Path) -> dict[str, str]:
    """Read the top-level ``spec.images`` mapping without a YAML dependency."""

    images: dict[str, str] = {}
    in_images = False
    for line in path.read_text().splitlines():
        if line == "  images:":
            in_images = True
            continue
        if not in_images:
            continue
        if line and not line.startswith("    "):
            break
        match = PLATFORM_IMAGE.fullmatch(line)
        if match:
            images[match.group(1)] = match.group(2)
    if not images:
        raise ValueError(f"{path}: spec.images must be a non-empty mapping")
    return images


def image_identity(ref: str) -> dict[str, str]:
    """Return the exact OCI root identity expected from Syft SPDX output."""

    locator, digest = ref.rsplit("@", 1)
    last_slash = locator.rfind("/")
    last_colon = locator.rfind(":")
    if last_colon > last_slash:
        repository = locator[:last_colon]
        tag = locator[last_colon + 1 :]
    else:
        repository = locator
        tag = ""
    segments = repository.split("/")
    if "." not in segments[0] and ":" not in segments[0] and segments[0] != "localhost":
        segments.insert(0, "docker.io")
        if len(segments) == 2:
            segments.insert(1, "library")
    canonical_repository = "/".join(segments)
    name = canonical_repository.rsplit("/", 1)[-1]
    qualifiers = f"repository_url={quote(canonical_repository, safe='')}"
    return {
        "root_name": name,
        "root_version": tag or digest,
        "digest": digest,
        "purl": f"pkg:oci/{quote(name, safe='')}@{digest}?{qualifiers}",
    }


def syft_platform_image_identity(
    ref: str, *, manifest_digest: str, architecture: str
) -> dict[str, str]:
    """Return Syft v1.38's exact SPDX identity for one runnable image manifest.

    Buildx publishes the signed image index, while Syft scans its selected
    platform manifest. Syft preserves the index as the source version but
    emits the selected manifest digest in the root package PURL/checksum.
    The registry source does not populate the PURL ``arch`` qualifier, so the
    exact expected qualifier is the empty value it emits. The workflow still
    verifies the selected linux/amd64 member independently before calling
    Syft. Callers must derive ``manifest_digest`` from that selected manifest
    before trusting this identity.
    """

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest):
        raise ValueError(
            f"platform manifest is not a sha256 digest: {manifest_digest!r}"
        )
    if architecture != "":
        raise ValueError(f"invalid platform architecture: {architecture!r}")
    index_identity = image_identity(ref)
    name = index_identity["root_name"]
    return {
        "root_name": name,
        "root_version": index_identity["root_version"],
        "digest": manifest_digest,
        "purl": (
            f"pkg:oci/{quote(name, safe='')}@{quote(manifest_digest, safe='')}"
            f"?arch={quote(architecture, safe='')}"
        ),
    }


def release_images(root: Path = ROOT) -> list[dict[str, str]]:
    """Return one stable matrix entry per digest-pinned release image."""

    lock = load_json(root / LOCK_PATH)
    runtime = lock.get("runtimeImages")
    if not isinstance(runtime, dict) or not runtime:
        raise ValueError("runtimeImages must be a non-empty object")
    source = lock.get("imageSources") or {}
    seed_relative = source.get("composeSeeds")
    if not isinstance(seed_relative, str) or not seed_relative:
        raise ValueError("imageSources.composeSeeds must be a non-empty string")
    seeds = load_json(root / seed_relative).get("seeds")
    if not isinstance(seeds, dict):
        raise ValueError(f"{seed_relative}: seeds must be an object")

    candidates: list[tuple[str, str]] = []
    for key, row in sorted(runtime.items()):
        if (
            isinstance(row, dict)
            and row.get("requiredDigestAtPreflight") is True
            and not row.get("ref")
        ):
            # Operator-supplied immutable images are unknown when the source
            # release SBOM matrix is assembled. Preflight validates the exact
            # deployed digest; do not fabricate a release target here.
            continue
        ref = row.get("ref") if isinstance(row, dict) else None
        candidates.append((f"runtime-{key}", str(ref or "")))
    candidates.extend(
        (f"seed-{key}", str(ref))
        for key, ref in sorted(seeds.items())
        if key.endswith("_IMAGE")
    )
    platform_relative = source.get("platformLock")
    if not isinstance(platform_relative, str) or not platform_relative:
        raise ValueError("imageSources.platformLock must be a non-empty string")
    candidates.extend(
        (f"platform-{key}", ref)
        for key, ref in sorted(platform_lock_images(root / platform_relative).items())
    )

    images: list[dict[str, str]] = []
    seen: set[str] = set()
    for key, ref in candidates:
        if not IMAGE_REF.fullmatch(ref):
            raise ValueError(f"{key}: image is not digest-pinned: {ref!r}")
        if ref in seen:
            continue
        seen.add(ref)
        image_id = re.sub(r"[^a-z0-9]+", "-", key.lower()).strip("-")
        images.append({"id": image_id, "image": ref, **image_identity(ref)})
    if not images:
        raise ValueError("no release images found")
    return images


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        payload = {"include": release_images(args.root.resolve())}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"sbom-targets: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
