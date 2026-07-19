#!/usr/bin/env python3
"""Reject malformed or empty SPDX JSON generated for a release artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


def meaningful_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def purl_identity(value: str) -> tuple[str, str, dict[str, list[str]]] | None:
    """Return the OCI purl name, version and qualifiers when well formed."""

    parsed = urlsplit(value)
    if parsed.scheme != "pkg" or not parsed.path.startswith("oci/"):
        return None
    identity = parsed.path.removeprefix("oci/")
    if "@" not in identity:
        return None
    name, version = identity.rsplit("@", 1)
    return unquote(name), unquote(version), parse_qs(
        parsed.query, keep_blank_values=True, strict_parsing=True
    )


def root_purls(root: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for reference in root.get("externalRefs") or []:
        if not isinstance(reference, dict):
            continue
        locator = reference.get("referenceLocator")
        if reference.get("referenceType") == "purl" and meaningful_string(locator):
            result.append(str(locator))
    return result


def matching_purl(actual: str, expected: str) -> bool:
    actual_identity = purl_identity(actual)
    expected_identity = purl_identity(expected)
    if actual_identity is None or expected_identity is None:
        return False
    actual_name, actual_version, actual_qualifiers = actual_identity
    expected_name, expected_version, expected_qualifiers = expected_identity
    return (
        actual_name == expected_name
        and actual_version == expected_version
        and actual_qualifiers == expected_qualifiers
    )


def verify(
    path: Path,
    *,
    expected_package: str | None = None,
    expected_target: str | None = None,
    expected_root_name: str | None = None,
    expected_root_version: str | None = None,
    expected_root_purl: str | None = None,
    expected_digest: str | None = None,
) -> list[str]:
    findings: list[str] = []
    try:
        if path.stat().st_size == 0:
            return ["file is empty"]
        value: Any = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [str(exc)]
    if not isinstance(value, dict):
        return ["document is not an object"]
    if not str(value.get("spdxVersion") or "").startswith("SPDX-"):
        findings.append("missing SPDX version")
    if not str(value.get("SPDXID") or "").startswith("SPDXRef-"):
        findings.append("missing document SPDXID")
    if not meaningful_string(value.get("documentNamespace")):
        findings.append("missing document namespace")
    if not meaningful_string(value.get("name")):
        findings.append("missing document name")
    creation_info = value.get("creationInfo")
    if not isinstance(creation_info, dict):
        findings.append("missing creationInfo")
    else:
        creators = creation_info.get("creators")
        if not isinstance(creators, list) or not any(
            isinstance(creator, str)
            and creator.partition(":")[0] in {"Organization", "Person", "Tool"}
            and bool(creator.partition(":")[2].strip())
            for creator in creators
        ):
            findings.append("missing meaningful creationInfo creators")
    packages = value.get("packages")
    if not isinstance(packages, list):
        findings.append("missing packages list")
        packages = []
    elif not packages:
        findings.append("packages list is empty")

    package_ids: set[str] = set()
    packages_by_id: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        package_id = str(package.get("SPDXID") or "")
        if package_id.startswith("SPDXRef-"):
            package_ids.add(package_id)
            packages_by_id[package_id] = package

    roots: set[str] = set()
    relationships = value.get("relationships")
    if not isinstance(relationships, list):
        findings.append("missing document root relationship")
    else:
        for relationship in relationships:
            if not isinstance(relationship, dict):
                continue
            if (
                relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
                and relationship.get("relationshipType") == "DESCRIBES"
                and relationship.get("relatedSpdxElement") in package_ids
            ):
                roots.add(str(relationship["relatedSpdxElement"]))
        if len(roots) != 1:
            findings.append("document must describe exactly one root package")
    if expected_package and roots:
        root = packages_by_id[next(iter(roots))]
        if root.get("name") != expected_package:
            findings.append(
                f"root package does not match expected package {expected_package!r}"
            )
    if roots:
        root = packages_by_id[next(iter(roots))]
        if expected_root_name and root.get("name") != expected_root_name:
            findings.append("root package name does not match the expected source")
        if expected_root_version and root.get("versionInfo") != expected_root_version:
            findings.append("root package version does not match the expected source")
        purls = root_purls(root)
        if expected_root_purl and not any(
            matching_purl(purl, expected_root_purl) for purl in purls
        ):
            findings.append("root package purl does not match the expected image")
        if expected_digest:
            digest = expected_digest.removeprefix("sha256:")
            checksum_match = any(
                isinstance(checksum, dict)
                and str(checksum.get("algorithm") or "").upper() == "SHA256"
                and checksum.get("checksumValue") == digest
                for checksum in root.get("checksums") or []
            )
            purl_match = any(
                (identity := purl_identity(purl)) is not None
                and identity[1] == expected_digest
                for purl in purls
            )
            if not checksum_match and not purl_match:
                findings.append("root package digest does not match the expected image")
    if expected_target and expected_target not in path.name:
        findings.append("artifact filename does not bind the expected target identity")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--expected-package")
    parser.add_argument("--expected-target")
    parser.add_argument("--expected-root-name")
    parser.add_argument("--expected-root-version")
    parser.add_argument("--expected-root-purl")
    parser.add_argument("--expected-digest")
    args = parser.parse_args(argv)
    failed = False
    for path in args.paths:
        findings = verify(
            path,
            expected_package=args.expected_package,
            expected_target=args.expected_target,
            expected_root_name=args.expected_root_name,
            expected_root_version=args.expected_root_version,
            expected_root_purl=args.expected_root_purl,
            expected_digest=args.expected_digest,
        )
        if findings:
            failed = True
            for finding in findings:
                print(f"verify-sbom: {path}: {finding}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
