#!/usr/bin/env python3
"""Fail closed unless a release event SHA still matches its remote tag."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def release_version(version_file: Path) -> str:
    """Read one strict SemVer line, terminated by exactly one LF."""

    try:
        contents = version_file.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read release version: {exc}") from exc
    try:
        version = contents[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("release VERSION must be ASCII strict SemVer") from exc
    if (
        SEMVER.fullmatch(version) is None
        or contents != version.encode("ascii") + b"\n"
    ):
        raise ValueError(
            "release VERSION must be one strict SemVer line terminated by exactly one LF"
        )
    return version


def verify_release_tag(tag: str, version: str) -> None:
    """Require the exact immutable release tag for the checked-out VERSION."""

    expected = f"v{version}"
    if tag != expected:
        raise ValueError(f"release tag must exactly match {expected!r}")


def remote_tag_target(output: str, tag_ref: str) -> str:
    """Return the unique commit target from ``git ls-remote`` output."""

    direct: set[str] = set()
    peeled: set[str] = set()
    for line in output.splitlines():
        fields = line.split("\t", maxsplit=1)
        if len(fields) != 2 or FULL_SHA.fullmatch(fields[0]) is None:
            continue
        if fields[1] == tag_ref:
            direct.add(fields[0])
        elif fields[1] == f"{tag_ref}^{{}}":
            peeled.add(fields[0])
    candidates = peeled or direct
    if len(candidates) != 1:
        raise ValueError("remote tag is absent, malformed, or resolves ambiguously")
    return candidates.pop()


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "git failed"
        raise ValueError(detail)
    return result.stdout


def verify_release_event(tag: str, target_sha: str, version_file: Path) -> None:
    verify_release_tag(tag, release_version(version_file))
    if FULL_SHA.fullmatch(target_sha) is None:
        raise ValueError("release target is not a full immutable commit SHA")
    tag_ref = f"refs/tags/{tag}"
    git("check-ref-format", "--allow-onelevel", tag_ref)

    local_head = git("rev-parse", "--verify", "HEAD^{commit}").strip()
    if local_head != target_sha:
        raise ValueError("checked-out source does not match the release event SHA")

    remote_output = git("ls-remote", "origin", tag_ref, f"{tag_ref}^{{}}")
    remote_target = remote_tag_target(remote_output, tag_ref)
    if remote_target != target_sha:
        raise ValueError("remote release tag no longer resolves to the release event SHA")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--version-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verify_release_event(args.tag, args.target_sha, args.version_file)
    except (ValueError, subprocess.TimeoutExpired) as exc:
        print(f"verify-release-event: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
