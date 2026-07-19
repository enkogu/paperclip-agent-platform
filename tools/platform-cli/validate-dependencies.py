#!/usr/bin/env python3
"""Validate immutable runtime images and downloaded dependency artifacts."""

from __future__ import annotations

import argparse
import ast
import base64
import glob
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


TOOL_RELATIVE = Path("tools/platform-cli")
ROOT = Path(__file__).resolve().parents[2]
LOCK_RELATIVE = "config/dependencies.lock.json"
DEFAULT_LOCK = ROOT / LOCK_RELATIVE
LICENSE_RELATIVE = "config/licenses.lock.json"
IMAGE_REF = re.compile(r"^[^\s@]+(?:[:][^\s@]+)?@sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SRI = re.compile(r"^sha512-([A-Za-z0-9+/]+={0,2})$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMPOSE_IMAGE = re.compile(r"^\s*image:\s*([^\s#]+)", re.MULTILINE)
COMPOSE_VARIABLE = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}$")
PLATFORM_IMAGE = re.compile(r"^    ([A-Za-z][A-Za-z0-9]*):\s+(\S+)\s*$")
FETCH_TO_FILE = re.compile(
    r"(?:\b(?:curl|wget)\b[^\n]*(?:\s-o\s|\s-O\s)|urlretrieve\s*\()"
)
HASHED_REQUIREMENT = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(?:\[[a-z0-9,-]+\])?=="
    r"[A-Za-z0-9][A-Za-z0-9.!+_-]* "
    r"--hash=sha256:[0-9a-f]{64}$"
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def python_dict(path: Path, assignment: str) -> dict[str, Any]:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == assignment
            for target in node.targets
        ):
            continue
        value = ast.literal_eval(node.value)
        if not isinstance(value, dict):
            break
        return value
    raise ValueError(f"{path}: missing literal dict assignment {assignment}")


def python_set(path: Path, assignment: str) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == assignment
            for target in node.targets
        ):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, set) and all(isinstance(item, str) for item in value):
            return value
        break
    raise ValueError(f"{path}: missing literal string set assignment {assignment}")


def mapping_literal(path: Path, key: str) -> str:
    matches = set(
        re.findall(
            rf'["\']{re.escape(key)}["\']\s*:\s*["\']([^"\']+)["\']', path.read_text()
        )
    )
    if len(matches) != 1:
        raise ValueError(
            f"{path}: expected one literal value for {key}, got {sorted(matches)}"
        )
    return matches.pop()


def shell_variable(path: Path, variable: str) -> str:
    matches = set(
        re.findall(
            rf"^\s*{re.escape(variable)}\s*=\s*(['\"])(.*?)\1\s*$",
            path.read_text(),
            re.MULTILINE,
        )
    )
    values = {value for _quote, value in matches}
    if len(values) != 1:
        raise ValueError(
            f"{path}: expected one literal shell value for {variable}, got {sorted(values)}"
        )
    return values.pop()


def add(findings: list[dict[str, str]], code: str, path: str, detail: str) -> None:
    findings.append({"code": code, "path": path, "detail": detail})


def valid_sha512_sri(value: str) -> bool:
    match = SRI.fullmatch(value)
    try:
        decoded = base64.b64decode(match.group(1), validate=True) if match else b""
    except ValueError:
        return False
    return len(decoded) == 64


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def declaration_value(root: Path, declaration: dict[str, str], key: str) -> str:
    path = root / declaration["path"]
    kind = declaration["kind"]
    if kind == "python-dict":
        return str(python_dict(path, declaration["assignment"]).get(key, ""))
    if kind == "python-set":
        return key if key in python_set(path, declaration["assignment"]) else ""
    if kind == "mapping-literal":
        return mapping_literal(path, key)
    if kind == "shell-variable":
        return shell_variable(path, declaration["variable"])
    if kind == "dockerfile-from":
        matches = re.findall(r"^FROM\s+(\S+)", path.read_text(), re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(f"{path}: expected exactly one FROM instruction")
        return matches[0]
    raise ValueError(f"unsupported declaration kind: {kind}")


def validate_images(
    root: Path, lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    runtime = lock.get("runtimeImages")
    if not isinstance(runtime, dict) or not runtime:
        add(
            findings,
            "runtime_images_missing",
            LOCK_RELATIVE,
            "runtimeImages must be a non-empty object",
        )
        runtime = {}
    for key, row in sorted(runtime.items()):
        path = f"runtimeImages.{key}"
        if not isinstance(row, dict):
            add(findings, "runtime_image_invalid", path, "entry must be an object")
            continue
        expected = str(row.get("ref") or "")
        required_at_preflight = row.get("requiredDigestAtPreflight") is True
        if not required_at_preflight and not IMAGE_REF.fullmatch(expected):
            add(findings, "image_not_digest_pinned", path, expected)
        if required_at_preflight and expected:
            add(findings, "operator_image_ref_must_not_be_committed", path, expected)
        declarations = row.get("declarations")
        if not isinstance(declarations, list) or not declarations:
            add(
                findings,
                "image_declaration_missing",
                path,
                "declarations must be non-empty",
            )
            declarations = []
        for declaration in declarations:
            source = str((declaration or {}).get("path") or path)
            try:
                actual = declaration_value(root, declaration, key)
            except (KeyError, OSError, SyntaxError, ValueError) as exc:
                add(findings, "image_declaration_invalid", source, str(exc))
                continue
            declaration_expected = key if required_at_preflight else expected
            if actual != declaration_expected:
                add(
                    findings,
                    "image_declaration_drift",
                    source,
                    f"{key}: {actual!r} != {declaration_expected!r}",
                )

        artifact = row.get("canonicalArtifact")
        if artifact is not None:
            if not isinstance(artifact, dict):
                add(findings, "canonical_artifact_invalid", path, repr(artifact))
                continue
            artifact_path = str(artifact.get("path") or "")
            artifact_sha256 = str(artifact.get("sha256") or "")
            try:
                actual_artifact_sha256 = file_sha256(root / artifact_path)
            except OSError as exc:
                add(findings, "canonical_artifact_invalid", artifact_path or path, str(exc))
            else:
                if (
                    not SHA256.fullmatch(artifact_sha256)
                    or actual_artifact_sha256 != artifact_sha256
                ):
                    add(
                        findings,
                        "canonical_artifact_hash_drift",
                        artifact_path or path,
                        f"{actual_artifact_sha256} != {artifact_sha256}",
                    )

        consumers = row.get("consumers") or []
        if not isinstance(consumers, list) or not consumers:
            add(
                findings,
                "image_consumer_missing",
                path,
                "consumers must be a non-empty list",
            )
            continue
        for consumer in consumers:
            source = root / str(consumer)
            try:
                text = source.read_text()
            except OSError as exc:
                add(findings, "image_consumer_invalid", str(consumer), str(exc))
                continue
            if re.search(rf"\b{re.escape(key)}\b", text) is None:
                add(
                    findings,
                    "image_consumer_drift",
                    str(consumer),
                    f"canonical key {key} is not referenced",
                )

    sources = lock.get("imageSources") or {}
    seed_relative = str(sources.get("composeSeeds") or "")
    try:
        seeds = load_json(root / seed_relative).get("seeds")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add(findings, "compose_seed_catalog_invalid", seed_relative, str(exc))
        seeds = {}
    if not isinstance(seeds, dict):
        add(
            findings,
            "compose_seed_catalog_invalid",
            seed_relative,
            "seeds must be an object",
        )
        seeds = {}
    seed_images = {
        key: str(value) for key, value in seeds.items() if key.endswith("_IMAGE")
    }
    if not seed_images:
        add(
            findings,
            "compose_seed_images_missing",
            seed_relative,
            "no *_IMAGE entries found",
        )
    for key, image in sorted(seed_images.items()):
        if not IMAGE_REF.fullmatch(image):
            add(
                findings,
                "compose_seed_image_not_digest_pinned",
                seed_relative,
                f"{key}={image}",
            )

    patterns = sources.get("directComposeGlobs") or []
    compose_paths: set[Path] = set()
    for pattern in patterns:
        compose_paths.update(Path(path) for path in glob.glob(str(root / pattern)))
    if not compose_paths:
        add(
            findings,
            "compose_sources_missing",
            LOCK_RELATIVE,
            "no Compose files matched",
        )
    known_variables = set(seed_images) | set(runtime)
    used_seed_images: set[str] = set()
    for compose in sorted(compose_paths):
        relative = str(compose.relative_to(root))
        for image in COMPOSE_IMAGE.findall(compose.read_text()):
            variable = COMPOSE_VARIABLE.fullmatch(image)
            if variable:
                key = variable.group(1)
                if key in seed_images:
                    used_seed_images.add(key)
                if key not in known_variables:
                    add(
                        findings,
                        "compose_image_variable_unlocked",
                        relative,
                        key,
                    )
            elif not IMAGE_REF.fullmatch(image):
                add(findings, "compose_image_not_digest_pinned", relative, image)
    for key in sorted(set(seed_images) - used_seed_images):
        add(
            findings,
            "compose_seed_image_unused",
            seed_relative,
            key,
        )

    config_path = root / TOOL_RELATIVE / "server-config.py"
    try:
        defaults = python_dict(config_path, "ONE_TIME_MIGRATION_SEEDS")
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "runtime_defaults_invalid",
            str(config_path.relative_to(root)),
            str(exc),
        )
        defaults = {}
    for key, value in sorted(defaults.items()):
        if key.endswith("_IMAGE") and not IMAGE_REF.fullmatch(str(value)):
            add(
                findings,
                "runtime_default_image_not_digest_pinned",
                "tools/platform-cli/server-config.py",
                f"{key}={value}",
            )

    runtime_default_images = {
        key
        for key in defaults
        if key.endswith("_IMAGE")
        and key not in seed_images
    }
    for key in sorted(runtime_default_images - set(runtime)):
        add(
            findings,
            "runtime_default_image_missing_from_lock",
            "tools/platform-cli/server-config.py",
            key,
        )
def all_version_values(root: Path) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    defaults = python_dict(
        root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
    )
    for key, value in defaults.items():
        values.setdefault(str(key), set()).add(str(value))
    daytona = (root / "deployment/steps/daytona.sh").read_text()
    for key, value in re.findall(
        r'["\']([A-Z][A-Z0-9_]*VERSION)["\']\s*:\s*["\']([^"\']+)["\']', daytona
    ):
        values.setdefault(key, set()).add(value)
    return values


def validate_npm(
    root: Path, lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    packages = lock.get("npmPackages")
    if not isinstance(packages, dict) or not packages:
        add(
            findings,
            "npm_packages_missing",
            LOCK_RELATIVE,
            "npmPackages must be non-empty",
        )
        return
    versions = all_version_values(root)
    try:
        canonical_defaults = python_dict(
            root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "npm_canonical_defaults_invalid",
            "tools/platform-cli/server-config.py",
            str(exc),
        )
        canonical_defaults = {}

    registry = str((lock.get("metadata") or {}).get("npmRegistry") or "")
    if not registry.startswith("https://"):
        add(
            findings,
            "npm_registry_invalid",
            "metadata.npmRegistry",
            registry,
        )
    registry_prefix = registry.rstrip("/") + "/"

    configured_install_sets = lock.get("npmLockfiles") or []
    if not isinstance(configured_install_sets, list) or not configured_install_sets:
        add(
            findings,
            "npm_lockfiles_missing",
            LOCK_RELATIVE,
            "npmLockfiles must be a non-empty list",
        )
        configured_install_sets = []
    lock_documents: dict[str, dict[str, Any]] = {}
    root_dependency_names: set[str] = set()
    for index, install_set in enumerate(configured_install_sets):
        contract_path = f"npmLockfiles[{index}]"
        if not isinstance(install_set, dict):
            add(
                findings,
                "npm_install_set_invalid",
                contract_path,
                "entry must be an object",
            )
            continue
        relative = str(install_set.get("lockfile") or "")
        manifest_relative = str(install_set.get("manifest") or "")
        consumer_relative = str(install_set.get("consumer") or "")
        install_consumer_relative = str(
            install_set.get("installConsumer") or consumer_relative
        )
        relative_paths = (relative, manifest_relative, consumer_relative)
        if any(
            not value or Path(value).is_absolute() or ".." in Path(value).parts
            for value in relative_paths
        ):
            add(
                findings,
                "npm_install_set_path_invalid",
                contract_path,
                repr(relative_paths),
            )
            continue
        path = root / relative
        manifest_path = root / manifest_relative
        consumer_path = root / consumer_relative
        install_consumer_path = root / install_consumer_relative
        if path.with_name("package.json") != manifest_path:
            add(
                findings,
                "npm_install_set_layout_invalid",
                contract_path,
                "manifest and lockfile must share one directory",
            )
        try:
            consumer_text = consumer_path.read_text()
        except OSError as exc:
            add(findings, "npm_install_consumer_invalid", consumer_relative, str(exc))
            consumer_text = ""
        try:
            install_consumer_text = install_consumer_path.read_text()
        except OSError as exc:
            add(
                findings,
                "npm_install_consumer_invalid",
                install_consumer_relative,
                str(exc),
            )
            install_consumer_text = ""
        for required_install_token in (
            "npm" + " ci",
            "--omit=dev",
            "--ignore-scripts",
            "--registry=",
        ):
            if required_install_token not in install_consumer_text:
                add(
                    findings,
                    "npm_install_mode_drift",
                    install_consumer_relative,
                    required_install_token,
                )
        direct_hash_contract = "manifestSha256" in install_set
        hash_sources = (
            ("manifestSha256", "manifestSha256Key", manifest_path),
            ("lockSha256", "lockSha256Key", path),
        )
        if not direct_hash_contract:
            hash_sources += (("consumerSha256", "consumerSha256Key", consumer_path),)
        for direct_field, key_field, source in hash_sources:
            key = str(install_set.get(key_field) or "")
            try:
                actual_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            except OSError as exc:
                add(findings, "npm_install_artifact_invalid", str(source), str(exc))
                continue
            if direct_hash_contract:
                if str(install_set.get(direct_field) or "") != actual_sha256:
                    add(
                        findings,
                        "npm_install_hash_contract_drift",
                        contract_path,
                        f"{direct_field} does not bind {source.relative_to(root)}",
                    )
                continue
            if not key or key not in consumer_text:
                add(
                    findings,
                    "npm_install_hash_not_enforced",
                    contract_path,
                    f"consumer does not reference {key_field}={key!r}",
                )
            if canonical_defaults.get(key) != actual_sha256:
                add(
                    findings,
                    "npm_install_hash_canonical_drift",
                    contract_path,
                    f"{key} does not bind {source.relative_to(root)}",
                )
        try:
            document = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            add(findings, "npm_lock_invalid", relative, str(exc))
            continue
        lock_documents[relative] = document
        if document.get("lockfileVersion") != 3:
            add(
                findings,
                "npm_lock_version_invalid",
                relative,
                str(document.get("lockfileVersion")),
            )
        lock_packages = document.get("packages") or {}
        if not isinstance(lock_packages, dict):
            add(
                findings,
                "npm_lock_packages_invalid",
                relative,
                "packages must be an object",
            )
            continue
        try:
            manifest = load_json(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            add(
                findings,
                "npm_manifest_invalid",
                str(manifest_path.relative_to(root)),
                str(exc),
            )
            manifest = {}
        manifest_dependencies = manifest.get("dependencies") or {}
        root_dependencies = (
            lock_packages.get("", {}).get("dependencies")
            if isinstance(lock_packages.get(""), dict)
            else None
        )
        if manifest_dependencies != root_dependencies:
            add(
                findings,
                "npm_manifest_lock_drift",
                relative,
                "package.json dependencies differ from package-lock root dependencies",
            )
        if isinstance(manifest_dependencies, dict):
            root_dependency_names.update(str(value) for value in manifest_dependencies)
        if (
            manifest.get("private") is not True
            or manifest.get("os") != ["linux"]
            or manifest.get("cpu") != ["x64"]
        ):
            add(
                findings,
                "npm_manifest_platform_drift",
                manifest_relative,
                "expected private Linux x64 install manifest",
            )
        for package_path, package in lock_packages.items():
            if not package_path:
                continue
            if not isinstance(package, dict) or not package.get("version"):
                add(
                    findings,
                    "npm_lock_package_unversioned",
                    relative,
                    package_path,
                )
                continue
            resolved = str(package.get("resolved") or "")
            if resolved:
                if not valid_sha512_sri(str(package.get("integrity") or "")):
                    add(
                        findings,
                        "npm_lock_package_unverified",
                        relative,
                        package_path,
                    )
                if registry_prefix != "/" and not resolved.startswith(registry_prefix):
                    add(
                        findings,
                        "npm_lock_registry_drift",
                        relative,
                        f"{package_path}: {resolved}",
                    )

    for package_name in sorted(root_dependency_names - set(packages)):
        add(
            findings,
            "npm_root_package_missing_from_contract",
            LOCK_RELATIVE,
            package_name,
        )
    # A locked platform binary may be an optional dependency of its public
    # wrapper (for example Codex/Claude's Linux x64 launcher).  It is not a
    # root manifest dependency, but it must still have an explicit integrity
    # contract.  Admit only an alias whose declared wrapper is a root package.
    contract_package_names = set(root_dependency_names)
    for package_name, row in packages.items():
        if (
            isinstance(row, dict)
            and str(row.get("aliasOf") or "") in root_dependency_names
        ):
            contract_package_names.add(package_name)
    for package_name in sorted(set(packages) - contract_package_names):
        add(
            findings,
            "npm_contract_package_not_installed",
            f"npmPackages.{package_name}",
            package_name,
        )

    for name, row in sorted(packages.items()):
        path = f"npmPackages.{name}"
        if not isinstance(row, dict):
            add(findings, "npm_package_invalid", path, "entry must be an object")
            continue
        version = str(row.get("version") or "")
        if not version or version in {"latest", "next", "main", "master", "*"}:
            add(findings, "npm_version_floating", path, version)
        integrity = str(row.get("integrity") or "")
        if not valid_sha512_sri(integrity):
            add(findings, "npm_integrity_invalid", path, integrity)
        integrity_key = str(row.get("integrityKey") or "")
        if not integrity_key:
            add(findings, "npm_integrity_key_missing", path, "integrityKey is required")
        elif canonical_defaults.get(integrity_key) != integrity:
            add(
                findings,
                "npm_integrity_declaration_drift",
                path,
                f"{integrity_key} does not declare the locked integrity",
            )
        version_keys = row.get("versionKeys")
        if version_keys is None and row.get("versionKey"):
            version_keys = [row.get("versionKey")]
        if not isinstance(version_keys, list) or not version_keys:
            add(
                findings,
                "npm_version_key_missing",
                path,
                "versionKeys must be a non-empty list",
            )
            version_keys = []
        canonical_version = str(row.get("canonicalVersion") or version)
        for version_key in version_keys:
            if canonical_version not in versions.get(str(version_key), set()):
                add(
                    findings,
                    "npm_version_declaration_drift",
                    path,
                    f"{version_key} does not declare {canonical_version}",
                )
        tarball = str(row.get("tarball") or "")
        if not tarball.startswith(registry_prefix):
            add(findings, "npm_tarball_invalid", path, tarball)

        package_nodes: list[tuple[str, dict[str, Any]]] = []
        node_path = f"node_modules/{name}"
        for relative, document in lock_documents.items():
            lock_packages = document.get("packages") or {}
            package = (
                lock_packages.get(node_path)
                if isinstance(lock_packages, dict)
                else None
            )
            if isinstance(package, dict):
                package_nodes.append((relative, package))
        if not package_nodes:
            add(
                findings,
                "npm_package_absent_from_locks",
                path,
                node_path,
            )
        for relative, package in package_nodes:
            observed = (
                str(package.get("version") or ""),
                str(package.get("integrity") or ""),
                str(package.get("resolved") or ""),
            )
            expected = (version, integrity, tarball)
            if observed != expected:
                add(
                    findings,
                    "npm_package_lock_drift",
                    relative,
                    f"{name}: {observed!r} != {expected!r}",
                )

        install_name = str(row.get("aliasOf") or name)
        install_paths = row.get("installPaths") or []
        if not isinstance(install_paths, list) or not install_paths:
            add(
                findings,
                "npm_install_path_missing",
                path,
                "installPaths must be non-empty",
            )
        for install_path in install_paths:
            source = root / str(install_path)
            try:
                text = source.read_text()
            except OSError as exc:
                add(findings, "npm_install_path_invalid", str(install_path), str(exc))
                continue
            lock_install = "npm" + " ci" in text and (
                any(Path(relative).parent.name in text for relative in lock_documents)
                or (
                    source.name == "Dockerfile"
                    and "COPY package.json package-lock.json" in text
                )
            )
            if install_name not in text and name not in text and not lock_install:
                add(
                    findings,
                    "npm_install_declaration_missing",
                    str(install_path),
                    install_name,
                )


def validate_downloads(
    root: Path, lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    downloads = lock.get("downloads")
    if not isinstance(downloads, dict) or not downloads:
        add(
            findings,
            "downloads_missing",
            LOCK_RELATIVE,
            "downloads must be non-empty",
        )
        return
    try:
        canonical_defaults = python_dict(
            root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "download_canonical_defaults_invalid",
            "tools/platform-cli/server-config.py",
            str(exc),
        )
        canonical_defaults = {}

    consumer_paths: set[str] = set()
    for name, row in sorted(downloads.items()):
        path = f"downloads.{name}"
        if not isinstance(row, dict):
            add(findings, "download_invalid", path, "entry must be an object")
            continue
        url = str(row.get("url") or "")
        digest = str(row.get("sha256") or "")
        if not url.startswith("https://"):
            add(findings, "download_url_insecure", path, url)
        if not SHA256.fullmatch(digest):
            add(findings, "download_sha256_invalid", path, digest)
            add(findings, "download_checksum_not_enforced", path, digest)
        bindings = row.get("bindings") or []
        if not isinstance(bindings, list) or not bindings:
            add(
                findings,
                "download_bindings_missing",
                path,
                "bindings must be a non-empty list",
            )
            continue
        for binding in bindings:
            if not isinstance(binding, dict):
                add(findings, "download_binding_invalid", path, repr(binding))
                continue
            relative = str(binding.get("consumer") or "")
            consumer_paths.add(relative)
            try:
                text = (root / relative).read_text()
            except OSError as exc:
                add(findings, "download_consumer_invalid", str(relative), str(exc))
                continue
            sha256_key = str(binding.get("sha256Key") or "")
            if not sha256_key or sha256_key not in text:
                add(
                    findings,
                    "download_checksum_not_enforced",
                    path,
                    f"consumer {relative} does not reference sha256Key {sha256_key!r}",
                )
            if canonical_defaults.get(sha256_key) != digest:
                add(
                    findings,
                    "download_checksum_canonical_drift",
                    path,
                    f"{sha256_key} does not declare the locked digest",
                )
            url_key = str(binding.get("urlKey") or "")
            version_key = str(binding.get("versionKey") or "")
            if not url_key and not version_key:
                add(
                    findings,
                    "download_identity_binding_missing",
                    path,
                    f"consumer {relative} needs urlKey or versionKey",
                )
            if url_key:
                if url_key not in text:
                    add(
                        findings,
                        "download_identity_not_enforced",
                        path,
                        f"consumer {relative} does not reference urlKey {url_key}",
                    )
                if canonical_defaults.get(url_key) != url:
                    add(
                        findings,
                        "download_url_canonical_drift",
                        path,
                        f"{url_key} does not declare the locked URL",
                    )
            if version_key:
                canonical_version = str(canonical_defaults.get(version_key) or "")
                if version_key not in text or not canonical_version:
                    add(
                        findings,
                        "download_identity_not_enforced",
                        path,
                        f"consumer {relative} does not bind {version_key}",
                    )
                elif canonical_version not in url:
                    add(
                        findings,
                        "download_version_canonical_drift",
                        path,
                        f"{version_key}={canonical_version!r} is absent from locked URL",
                    )
    executable_download_sources = {
        "deployment/steps/host.sh",
        "tools/platform-cli/server-toolhive.py",
    }
    signed_source_paths = {
        str(row.get("path") or "")
        for row in (lock.get("signedRepositories") or {}).values()
        if isinstance(row, dict)
    }
    for relative in sorted(
        executable_download_sources - consumer_paths - signed_source_paths
    ):
        add(
            findings,
            "download_source_unlocked",
            relative,
            "network-fetched executable is absent from downloads",
        )

    signed = lock.get("signedRepositories") or {}
    signed_paths: set[str] = set()
    for name, row in sorted(signed.items()):
        path = f"signedRepositories.{name}"
        if not isinstance(row, dict):
            add(findings, "signed_repository_invalid", path, "entry must be an object")
            continue
        relative = str(row.get("path") or "")
        signed_paths.add(relative)
        try:
            text = (root / relative).read_text()
        except OSError as exc:
            add(findings, "signed_repository_source_invalid", relative, str(exc))
            continue
        signed_by = str(row.get("signedBy") or "")
        if not signed_by or signed_by not in text:
            add(
                findings,
                "signed_repository_contract_drift",
                path,
                f"signedBy={signed_by!r}",
            )
        for value_field, key_field in (
            ("keyUrl", "keyUrlKey"),
            ("repositoryUrl", "repositoryUrlKey"),
            ("keySha256", "keySha256Key"),
            ("fingerprint", "fingerprintKey"),
        ):
            value = str(row.get(value_field) or "")
            canonical_key = str(row.get(key_field) or "")
            if not canonical_key or canonical_key not in text:
                add(
                    findings,
                    "signed_repository_contract_drift",
                    path,
                    f"{key_field}={canonical_key!r}",
                )
            if canonical_defaults.get(canonical_key) != value:
                add(
                    findings,
                    "signed_repository_canonical_drift",
                    path,
                    f"{canonical_key} does not declare {value!r}",
                )
        for field in ("keyUrl", "repositoryUrl"):
            value = str(row.get(field) or "")
            if not value.startswith("https://"):
                add(findings, "signed_repository_url_insecure", path, value)
        key_sha256 = str(row.get("keySha256") or "")
        if not SHA256.fullmatch(key_sha256):
            add(findings, "signed_repository_key_sha256_invalid", path, key_sha256)
        fingerprint = str(row.get("fingerprint") or "")
        if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
            add(
                findings,
                "signed_repository_fingerprint_invalid",
                path,
                fingerprint,
            )

    approved_fetch_paths = consumer_paths | signed_paths
    for relative in sorted(discover_network_fetch_sources(root)):
        if relative not in approved_fetch_paths:
            add(
                findings,
                "download_source_unlocked",
                relative,
                "network-fetched artifact is absent from downloads or signedRepositories",
            )

    approved_npm_paths = {
        str(path)
        for row in (lock.get("npmPackages") or {}).values()
        if isinstance(row, dict)
        for path in row.get("installPaths") or []
    }
    for relative in sorted(discover_npm_install_sources(root)):
        if relative not in approved_npm_paths:
            add(
                findings,
                "npm_install_source_unlocked",
                relative,
                "npm/npx runtime install is absent from npmPackages",
            )


def validate_python_distributions(
    root: Path, lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    distributions = lock.get("pythonDistributions")
    if not isinstance(distributions, dict) or not distributions:
        add(
            findings,
            "python_distributions_missing",
            LOCK_RELATIVE,
            "pythonDistributions must be a non-empty object",
        )
        return
    try:
        canonical_defaults = python_dict(
            root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "python_distribution_defaults_invalid",
            "tools/platform-cli/server-config.py",
            str(exc),
        )
        canonical_defaults = {}

    downloads = lock.get("downloads") or {}
    for name, row in sorted(distributions.items()):
        contract_path = f"pythonDistributions.{name}"
        if not isinstance(row, dict):
            add(findings, "python_distribution_invalid", contract_path, repr(row))
            continue
        paths = {
            field: str(row.get(field) or "")
            for field in ("manifest", "requirements", "consumer", "projectionConsumer")
        }
        if any(
            not relative or Path(relative).is_absolute() or ".." in Path(relative).parts
            for relative in paths.values()
        ):
            add(
                findings,
                "python_distribution_path_invalid",
                contract_path,
                repr(paths),
            )
            continue
        resolved = {field: root / relative for field, relative in paths.items()}
        try:
            manifest = load_json(resolved["manifest"])
            requirements_text = resolved["requirements"].read_text()
            consumer_text = resolved["consumer"].read_text()
            projection_text = resolved["projectionConsumer"].read_text()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            add(findings, "python_distribution_asset_invalid", contract_path, str(exc))
            continue

        manifest_sha256 = hashlib.sha256(resolved["manifest"].read_bytes()).hexdigest()
        requirements_sha256 = hashlib.sha256(
            resolved["requirements"].read_bytes()
        ).hexdigest()
        if row.get("manifestSha256") != manifest_sha256:
            add(
                findings,
                "python_manifest_hash_drift",
                contract_path,
                manifest_sha256,
            )
        if row.get("requirementsSha256") != requirements_sha256:
            add(
                findings,
                "python_requirements_hash_drift",
                contract_path,
                requirements_sha256,
            )

        identity = manifest.get("hermes") or {}
        wheel_download = downloads.get(str(row.get("wheelDownload") or "")) or {}
        sigstore_download = downloads.get(
            str(row.get("sigstoreBundleDownload") or "")
        ) or {}
        expected_wheel = {
            "filename": Path(str(wheel_download.get("url") or "")).name,
            "url": wheel_download.get("url"),
            "sha256": wheel_download.get("sha256"),
            "size": 9569078,
        }
        expected_provenance = {
            "pypi": row.get("pypiProvenanceUrl"),
            "signerIdentity": row.get("signerIdentity"),
            "signerIssuer": row.get("signerIssuer"),
            "signerRepository": row.get("signerRepository"),
            "signerTagRef": row.get("signerTagRef"),
            "sigstoreBundleUrl": sigstore_download.get("url"),
            "sigstoreBundleSha256": sigstore_download.get("sha256"),
            "sigstoreVerifierImage": row.get("sigstoreVerifierImage"),
            "sigstoreVerifierPackageVersion": row.get(
                "sigstoreVerifierPackageVersion"
            ),
        }
        projected_provenance = {
            "sigstoreVerifierImage": canonical_defaults.get("HERMES_SIGSTORE_VERIFIER_IMAGE"),
            "sigstoreVerifierPackageVersion": canonical_defaults.get(
                "HERMES_SIGSTORE_PACKAGE_VERSION"
            ),
        }
        if (
            not isinstance(identity, dict)
            or identity.get("distribution") != name
            or identity.get("version") != row.get("version")
            or identity.get("extras") != row.get("extras")
            or identity.get("wheel") != expected_wheel
            or identity.get("provenance") != expected_provenance
        ):
            add(
                findings,
                "python_distribution_identity_drift",
                contract_path,
                repr(identity),
            )
        if any(
            projected_provenance[name] != expected_provenance[name]
            for name in projected_provenance
        ):
            add(
                findings,
                "python_distribution_canonical_drift",
                contract_path,
                repr(projected_provenance),
            )
        for value in (
            row.get("version"),
            expected_wheel["sha256"],
            expected_provenance["sigstoreBundleSha256"],
            expected_provenance["signerIdentity"],
            expected_provenance["signerIssuer"],
            expected_provenance["signerRepository"],
            expected_provenance["signerTagRef"],
            str(row.get("manifestSha256") or ""),
        ):
            if not value or str(value) not in consumer_text:
                add(
                    findings,
                    "python_distribution_identity_not_enforced",
                    paths["consumer"],
                    str(value),
                )
        for marker in (
            "HERMES_WHEEL_URL",
            "HERMES_PYPI_PROVENANCE_URL",
            "HERMES_SIGSTORE_BUNDLE_URL",
            "HERMES_SIGSTORE_PACKAGE_VERSION",
            "HERMES_SIGSTORE_VERIFIER_IMAGE",
        ):
            if marker not in consumer_text:
                add(
                    findings,
                    "python_distribution_identity_not_enforced",
                    paths["consumer"],
                    marker,
                )

        python_lock = manifest.get("python") or {}
        requirement_rows = [
            line.strip()
            for line in requirements_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if (
            not isinstance(python_lock, dict)
            or python_lock.get("requirementsFile") != resolved["requirements"].name
            or python_lock.get("requirementsSha256") != requirements_sha256
            or python_lock.get("packageCount") != len(requirement_rows)
            or python_lock.get("allowDependencySourceBuilds") is not False
        ):
            add(
                findings,
                "python_lock_drift",
                contract_path,
                repr(python_lock),
            )
        for line_number, requirement in enumerate(requirement_rows, 1):
            if HASHED_REQUIREMENT.fullmatch(requirement) is None:
                add(
                    findings,
                    "python_requirement_unlocked",
                    paths["requirements"],
                    f"entry {line_number}",
                )

        for flag in (
            "--require-hashes",
            "--only-binary=:all:",
        ):
            if flag not in consumer_text:
                add(
                    findings,
                    "python_install_flag_missing",
                    paths["consumer"],
                    flag,
                )
        for asset in (resolved["manifest"].name, resolved["requirements"].name):
            if asset not in projection_text:
                add(
                    findings,
                    "python_projection_missing",
                    paths["projectionConsumer"],
                    asset,
                )

        os_lock = manifest.get("osPackages") or {}
        canonical_key = str(row.get("canonicalPackagesKey") or "")
        package_names = os_lock.get("names") if isinstance(os_lock, dict) else None
        canonical_pins = str(canonical_defaults.get(canonical_key) or "")
        parsed_pins: dict[str, str] = {}
        for item in canonical_pins.split(",") if canonical_pins else ():
            package, separator, version = item.partition("=")
            if not separator or not package or not version or package in parsed_pins:
                add(
                    findings,
                    "python_system_package_pin_invalid",
                    contract_path,
                    item,
                )
                continue
            parsed_pins[package] = version
        if (
            not canonical_key
            or canonical_key not in consumer_text
            or not isinstance(package_names, list)
            or sorted(parsed_pins) != sorted(str(value) for value in package_names)
        ):
            add(
                findings,
                "python_system_package_contract_drift",
                contract_path,
                canonical_key,
            )


def validate_system_packages(
    root: Path, lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    packages = lock.get("systemPackages")
    if not isinstance(packages, dict) or not packages:
        add(
            findings,
            "system_packages_missing",
            LOCK_RELATIVE,
            "systemPackages must be a non-empty object",
        )
        return
    try:
        canonical_defaults = python_dict(
            root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "system_package_defaults_invalid",
            "tools/platform-cli/server-config.py",
            str(exc),
        )
        return
    for package, row in sorted(packages.items()):
        path = f"systemPackages.{package}"
        if not isinstance(row, dict):
            add(findings, "system_package_invalid", path, "entry must be an object")
            continue
        version = str(row.get("version") or "")
        version_key = str(row.get("versionKey") or "")
        provider = str(row.get("provider") or "")
        relative = str(row.get("path") or "")
        if not version or any(token in version for token in ("*", "latest")):
            add(findings, "system_package_version_floating", path, version)
        if not provider:
            add(findings, "system_package_provider_missing", path, provider)
        try:
            text = (root / relative).read_text()
        except OSError as exc:
            add(findings, "system_package_source_invalid", relative, str(exc))
            continue
        if package not in text or version_key not in text:
            add(
                findings,
                "system_package_contract_drift",
                path,
                f"{package} / {version_key}",
            )
        if canonical_defaults.get(version_key) != version:
            add(
                findings,
                "system_package_version_declaration_drift",
                path,
                f"{version_key} does not declare {version!r}",
            )


def embedded_image_package_artifacts(lock: dict[str, Any]) -> set[str]:
    """Return image/package identities that run inside an immutable image."""

    packages = lock.get("embeddedImagePackages") or {}
    if not isinstance(packages, dict):
        return set()
    result: set[str] = set()
    for row in packages.values():
        if not isinstance(row, dict):
            continue
        image_key = str(row.get("imageKey") or "")
        package_name = str(row.get("packageName") or "")
        version = str(row.get("version") or "")
        if image_key and package_name and version:
            result.add(f"{image_key}/{package_name}@{version}")
    return result


def validate_embedded_image_packages(
    root: Path, lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    """Bind image-resident package identities to the immutable runtime ABI."""

    packages = lock.get("embeddedImagePackages")
    if not isinstance(packages, dict) or not packages:
        add(
            findings,
            "embedded_image_packages_missing",
            LOCK_RELATIVE,
            "embeddedImagePackages must be a non-empty object",
        )
        return
    runtime = lock.get("runtimeImages") or {}
    try:
        defaults = python_dict(
            root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "embedded_image_package_defaults_invalid",
            "tools/platform-cli/server-config.py",
            str(exc),
        )
        defaults = {}
    identities: set[str] = set()
    for package_id, row in sorted(packages.items()):
        contract_path = f"embeddedImagePackages.{package_id}"
        if not isinstance(row, dict):
            add(findings, "embedded_image_package_invalid", contract_path, repr(row))
            continue
        image_key = str(row.get("imageKey") or "")
        package_name = str(row.get("packageName") or "")
        version = str(row.get("version") or "")
        version_key = str(row.get("versionKey") or "")
        consumer = str(row.get("consumer") or "")
        module_path = str(row.get("modulePath") or "")
        identity = f"{image_key}/{package_name}@{version}"
        if (
            image_key not in runtime
            or not package_name
            or SEMVER.fullmatch(version) is None
            or not version_key
            or not consumer
            or (module_path and not module_path.startswith("/"))
        ):
            add(findings, "embedded_image_package_invalid", contract_path, repr(row))
            continue
        if identity in identities:
            add(findings, "embedded_image_package_duplicate", contract_path, identity)
        identities.add(identity)
        if defaults.get(version_key) != version:
            add(
                findings,
                "embedded_image_package_version_drift",
                contract_path,
                f"{version_key} does not declare {version!r}",
            )
        try:
            consumer_text = (root / consumer).read_text()
        except OSError as exc:
            add(
                findings,
                "embedded_image_package_consumer_invalid",
                consumer,
                str(exc),
            )
            continue
        required_tokens = (image_key, package_name, version_key)
        if module_path:
            required_tokens += (module_path,)
        for required in required_tokens:
            if required not in consumer_text:
                add(
                    findings,
                    "embedded_image_package_identity_not_enforced",
                    consumer,
                    required,
                )


def validate_operator_runtime_evidence(
    lock: dict[str, Any], findings: list[dict[str, str]]
) -> None:
    """Require release-time evidence for an external operator-supplied image."""

    runtime = lock.get("runtimeImages") or {}
    for image_key, row in sorted(runtime.items()):
        if not isinstance(row, dict):
            continue
        evidence = row.get("operatorEvidence")
        if evidence is None:
            continue
        contract_path = f"runtimeImages.{image_key}.operatorEvidence"
        if not isinstance(evidence, dict) or row.get("requiredDigestAtPreflight") is not True:
            add(findings, "operator_runtime_evidence_invalid", contract_path, repr(evidence))
            continue
        source_url_key = str(evidence.get("sourceUrlKey") or "")
        revision_key = str(evidence.get("revisionKey") or "")
        upstream_component = str(evidence.get("upstreamComponent") or "")
        if not source_url_key or not revision_key or not upstream_component:
            add(findings, "operator_runtime_evidence_invalid", contract_path, repr(evidence))
            continue
        image = os.environ.get(image_key, "").strip()
        source_url = os.environ.get(source_url_key, "").strip()
        revision = os.environ.get(revision_key, "").strip()
        if not IMAGE_REF.fullmatch(image):
            add(
                findings,
                "operator_runtime_image_evidence_missing",
                image_key,
                "a release must provide an immutable image digest",
            )
        if not source_url.startswith("https://"):
            add(
                findings,
                "operator_runtime_source_evidence_missing",
                source_url_key,
                "a release must provide the exact fork source URL",
            )
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            add(
                findings,
                "operator_runtime_revision_evidence_missing",
                revision_key,
                "a release must provide the exact fork commit revision",
            )


def license_artifacts(root: Path, lock: dict[str, Any]) -> dict[str, set[str]]:
    """Return the direct artifact identities governed by the license catalog."""

    scopes = {
        name: set((lock.get(name) or {}).keys())
        for name in (
            "runtimeImages",
            "npmPackages",
            "downloads",
            "systemPackages",
            "pythonDistributions",
        )
    }
    seed_relative = str(((lock.get("imageSources") or {}).get("composeSeeds")) or "")
    try:
        seeds = load_json(root / seed_relative).get("seeds") or {}
    except (OSError, ValueError, json.JSONDecodeError):
        seeds = {}
    scopes["composeSeedImages"] = {
        str(key) for key in seeds if str(key).endswith("_IMAGE")
    }
    platform_relative = str(
        ((lock.get("imageSources") or {}).get("platformLock")) or ""
    )
    platform_keys: set[str] = set()
    try:
        in_images = False
        for line in (root / platform_relative).read_text().splitlines():
            if line == "  images:":
                in_images = True
                continue
            if not in_images:
                continue
            if line and not line.startswith("    "):
                break
            match = PLATFORM_IMAGE.fullmatch(line)
            if match:
                platform_keys.add(match.group(1))
    except OSError:
        pass
    scopes["platformLockImages"] = platform_keys
    scopes["embeddedImagePackages"] = embedded_image_package_artifacts(lock)
    return scopes


def validate_licenses(
    root: Path,
    lock: dict[str, Any],
    findings: list[dict[str, str]],
    catalog_path: Path | None = None,
) -> None:
    """Fail closed when a direct artifact has no approved delivery decision."""

    path = catalog_path or root / LICENSE_RELATIVE
    try:
        catalog = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add(findings, "license_catalog_invalid", LICENSE_RELATIVE, str(exc))
        return
    if (
        catalog.get("schemaVersion") != 1
        or catalog.get("kind") != "PublicCoreLicenseCatalog"
    ):
        add(
            findings,
            "license_catalog_schema_invalid",
            LICENSE_RELATIVE,
            "expected PublicCoreLicenseCatalog schemaVersion 1",
        )

    policy = catalog.get("policy") or {}
    components = catalog.get("components") or {}
    rules = catalog.get("artifactRules") or []
    allowed_expressions = set(policy.get("allowedLicenseExpressions") or [])
    allowed_decisions = set(policy.get("allowedDecisions") or [])
    denied_tokens = tuple(policy.get("deniedLicenseTokens") or [])
    if not isinstance(components, dict) or not components:
        add(
            findings,
            "license_components_missing",
            LICENSE_RELATIVE,
            "components must be a non-empty object",
        )
        return
    if not isinstance(rules, list) or not rules:
        add(
            findings,
            "license_rules_missing",
            LICENSE_RELATIVE,
            "artifactRules must be a non-empty list",
        )
        return

    for component_id, component in sorted(components.items()):
        contract_path = f"components.{component_id}"
        if not isinstance(component, dict):
            add(findings, "license_component_invalid", contract_path, repr(component))
            continue
        decision = str(component.get("decision") or "")
        expression = str(component.get("licenseExpression") or "")
        source_url = str(component.get("sourceUrl") or "")
        source_ref = str(component.get("sourceRef") or "")
        if decision not in allowed_decisions:
            add(findings, "license_decision_invalid", contract_path, decision)
        if not source_url.startswith("https://"):
            add(findings, "license_source_url_invalid", contract_path, source_url)
        if not source_ref or source_ref.lower() in {
            "head",
            "latest",
            "main",
            "master",
            "next",
        }:
            add(findings, "license_source_ref_floating", contract_path, source_ref)
        if decision == "approved-oss":
            if expression not in allowed_expressions:
                add(findings, "license_disallowed", contract_path, expression)
            if any(token.lower() in expression.lower() for token in denied_tokens):
                add(findings, "license_denied_token", contract_path, expression)
        elif decision in {
            "operator-provided-proprietary-tool",
            "operator-provided-external-runtime",
        }:
            if component.get("redistributed") is not False:
                add(
                    findings,
                    "operator_tool_redistribution_invalid"
                    if decision == "operator-provided-proprietary-tool"
                    else "operator_runtime_redistribution_invalid",
                    contract_path,
                    "operator-provided artifacts must declare redistributed=false",
                )

    runtime_images = lock.get("runtimeImages") or {}
    for image_key, row in sorted(runtime_images.items()):
        evidence = row.get("operatorEvidence") if isinstance(row, dict) else None
        if not isinstance(evidence, dict):
            continue
        upstream_component = str(evidence.get("upstreamComponent") or "")
        upstream = components.get(upstream_component) or {}
        if (
            not isinstance(upstream, dict)
            or upstream.get("decision") != "approved-oss"
            or not str(upstream.get("licenseExpression") or "")
            or (
                image_key == "MTE_PAPERCLIP_IMAGE"
                and upstream.get("licenseExpression") != "MIT"
            )
        ):
            add(
                findings,
                "operator_runtime_upstream_provenance_invalid",
                f"runtimeImages.{image_key}.operatorEvidence",
                upstream_component,
            )

    compiled_rules: list[tuple[str, re.Pattern[str], str]] = []
    for index, rule in enumerate(rules):
        contract_path = f"artifactRules[{index}]"
        if not isinstance(rule, dict):
            add(findings, "license_rule_invalid", contract_path, repr(rule))
            continue
        scope = str(rule.get("scope") or "")
        pattern = str(rule.get("pattern") or "")
        component_id = str(rule.get("component") or "")
        if not pattern.startswith("^") or not pattern.endswith("$"):
            add(findings, "license_rule_unanchored", contract_path, pattern)
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            add(findings, "license_rule_invalid", contract_path, str(exc))
            continue
        if component_id not in components:
            add(
                findings,
                "license_rule_component_missing",
                contract_path,
                component_id,
            )
        compiled_rules.append((scope, compiled, component_id))

    active_components: set[str] = set()
    for scope, keys in sorted(license_artifacts(root, lock).items()):
        for key in sorted(keys):
            matches = [
                component_id
                for rule_scope, pattern, component_id in compiled_rules
                if rule_scope == scope and pattern.fullmatch(key)
            ]
            artifact_path = f"{scope}.{key}"
            if not matches:
                add(
                    findings,
                    "license_metadata_missing",
                    artifact_path,
                    "no artifact rule matched",
                )
                continue
            if len(matches) != 1:
                add(
                    findings,
                    "license_metadata_ambiguous",
                    artifact_path,
                    repr(matches),
                )
                continue
            component_id = matches[0]
            active_components.add(component_id)
            component = components.get(component_id) or {}
            if component.get("decision") == "blocked":
                add(
                    findings,
                    "license_component_blocked",
                    artifact_path,
                    f"{component_id}: {component.get('reason') or 'blocked by policy'}",
                )

    enablement = policy.get("operatorHarnessEnablement") or {}
    enablement_key = str(enablement.get("key") or "")
    required_components = set(enablement.get("requiredComponents") or [])
    active_operator_components = {
        component_id
        for component_id in active_components
        if (components.get(component_id) or {}).get("decision")
        == "operator-provided-proprietary-tool"
    }
    if active_operator_components != required_components:
        add(
            findings,
            "operator_harness_component_drift",
            "policy.operatorHarnessEnablement.requiredComponents",
            f"active={sorted(active_operator_components)!r} required={sorted(required_components)!r}",
        )
    try:
        defaults = python_dict(
            root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
        )
        example_text = (root / "config/platform.env.example").read_text()
    except (OSError, SyntaxError, ValueError) as exc:
        add(
            findings,
            "operator_harness_enablement_default_invalid",
            enablement_key,
            str(exc),
        )
        defaults = {}
        example_text = ""
    expected_default = str(enablement.get("default") or "")
    if (
        not enablement_key
        or expected_default != "false"
        or defaults.get(enablement_key) != "false"
        or re.search(
            rf"^{re.escape(enablement_key)}=false$", example_text, re.MULTILINE
        )
        is None
    ):
        add(
            findings,
            "operator_harness_enablement_default_invalid",
            enablement_key or "policy.operatorHarnessEnablement.key",
            "canonical and example defaults must both be exactly false",
        )
    for consumer in enablement.get("installerConsumers") or []:
        try:
            text = (root / str(consumer)).read_text()
        except OSError as exc:
            add(
                findings,
                "operator_harness_consumer_invalid",
                str(consumer),
                str(exc),
            )
            continue
        if (
            enablement_key not in text
            or "operator-provided proprietary harnesses are not enabled" not in text
            or re.search(r"(?:==|!=)\s*[\"']true[\"']", text) is None
        ):
            add(
                findings,
                "operator_harness_enablement_not_enforced",
                str(consumer),
                enablement_key,
            )


def executable_sources(root: Path) -> list[Path]:
    result: list[Path] = []
    for directory in (
        root / TOOL_RELATIVE,
        root / "deployment/steps",
        root / "deployment/agent-runtime",
    ):
        if not directory.is_dir():
            continue
        result.extend(
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix in {".py", ".sh"}
        )
    return result


def discover_network_fetch_sources(root: Path) -> set[str]:
    result: set[str] = set()
    for path in executable_sources(root):
        for line in path.read_text(errors="ignore").splitlines():
            if FETCH_TO_FILE.search(line) and (
                "https://" in line or "URL" in line or "urlretrieve" in line
            ):
                result.add(str(path.relative_to(root)))
                break
    return result


def discover_npm_install_sources(root: Path) -> set[str]:
    result: set[str] = set()
    for path in executable_sources(root):
        text = path.read_text(errors="ignore")
        if re.search(r"\bnpm\s+(?:install|i|ci)\b|\bnpx\s+--yes\b", text):
            result.add(str(path.relative_to(root)))
    return result


def validate(
    root: Path = ROOT,
    lock_path: Path | None = None,
    *,
    require_operator_evidence: bool = True,
) -> list[dict[str, str]]:
    lock_path = lock_path or root / LOCK_RELATIVE
    try:
        lock = load_json(lock_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [{"code": "lock_invalid", "path": str(lock_path), "detail": str(exc)}]
    findings: list[dict[str, str]] = []
    if lock.get("schemaVersion") != 1 or lock.get("kind") != "RuntimeDependencyLock":
        add(
            findings,
            "lock_schema_invalid",
            str(lock_path),
            "expected RuntimeDependencyLock schemaVersion 1",
        )
    validate_images(root, lock, findings)
    validate_npm(root, lock, findings)
    validate_downloads(root, lock, findings)
    validate_python_distributions(root, lock, findings)
    validate_system_packages(root, lock, findings)
    validate_embedded_image_packages(root, lock, findings)
    if require_operator_evidence:
        validate_operator_runtime_evidence(lock, findings)
    validate_licenses(root, lock, findings)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--lock", type=Path)
    parser.add_argument(
        "--source-contract-only",
        action="store_true",
        help="validate source contracts before an external image digest exists",
    )
    args = parser.parse_args(argv)
    findings = validate(
        args.root.resolve(),
        args.lock.resolve() if args.lock else None,
        require_operator_evidence=not args.source_contract_only,
    )
    payload = {
        "ok": not findings,
        "kind": "RuntimeDependencyValidation",
        "summary": {"findings": len(findings)},
        "findings": findings,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
