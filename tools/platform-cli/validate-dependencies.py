#!/usr/bin/env python3
"""Validate immutable runtime images and downloaded dependency artifacts."""

from __future__ import annotations

import argparse
import ast
import base64
import glob
import json
import re
import sys
from pathlib import Path
from typing import Any


TOOL_RELATIVE = Path("tools/platform-cli")
ROOT = Path(__file__).resolve().parents[2]
LOCK_RELATIVE = "config/dependencies.lock.json"
DEFAULT_LOCK = ROOT / LOCK_RELATIVE
IMAGE_REF = re.compile(r"^[^\s@]+(?:[:][^\s@]+)?@sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SRI = re.compile(r"^sha512-([A-Za-z0-9+/]+={0,2})$")
COMPOSE_IMAGE = re.compile(r"^\s*image:\s*([^\s#]+)", re.MULTILINE)
COMPOSE_VARIABLE = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}$")
FETCH_TO_FILE = re.compile(
    r"(?:\b(?:curl|wget)\b[^\n]*(?:\s-o\s|\s-O\s)|urlretrieve\s*\()"
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


def declaration_value(root: Path, declaration: dict[str, str], key: str) -> str:
    path = root / declaration["path"]
    kind = declaration["kind"]
    if kind == "python-dict":
        return str(python_dict(path, declaration["assignment"]).get(key, ""))
    if kind == "mapping-literal":
        return mapping_literal(path, key)
    if kind == "shell-variable":
        return shell_variable(path, declaration["variable"])
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
        if not IMAGE_REF.fullmatch(expected):
            add(findings, "image_not_digest_pinned", path, expected)
        declarations = row.get("declarations")
        if not isinstance(declarations, list) or not declarations:
            add(
                findings,
                "image_declaration_missing",
                path,
                "declarations must be non-empty",
            )
            continue
        for declaration in declarations:
            source = str((declaration or {}).get("path") or path)
            try:
                actual = declaration_value(root, declaration, key)
            except (KeyError, OSError, SyntaxError, ValueError) as exc:
                add(findings, "image_declaration_invalid", source, str(exc))
                continue
            if actual != expected:
                add(
                    findings,
                    "image_declaration_drift",
                    source,
                    f"{key}: {actual!r} != {expected!r}",
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
    for compose in sorted(compose_paths):
        relative = str(compose.relative_to(root))
        for image in COMPOSE_IMAGE.findall(compose.read_text()):
            variable = COMPOSE_VARIABLE.fullmatch(image)
            if variable:
                if variable.group(1) not in known_variables:
                    add(
                        findings,
                        "compose_image_variable_unlocked",
                        relative,
                        variable.group(1),
                    )
            elif not IMAGE_REF.fullmatch(image):
                add(findings, "compose_image_not_digest_pinned", relative, image)

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

    daytona_path = root / "deployment/steps/60-daytona.sh"
    daytona_text = daytona_path.read_text()
    for key, value in sorted(
        set(
            re.findall(
                r'["\'](MTE_DAYTONA_[A-Z0-9_]*_IMAGE)["\']\s*:\s*["\']([^"\']+)["\']',
                daytona_text,
            )
        )
    ):
        if not IMAGE_REF.fullmatch(value):
            add(
                findings,
                "daytona_image_not_digest_pinned",
                str(daytona_path.relative_to(root)),
                f"{key}={value}",
            )
        if key not in runtime:
            add(
                findings,
                "daytona_image_missing_from_lock",
                str(daytona_path.relative_to(root)),
                key,
            )


def all_version_values(root: Path) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    defaults = python_dict(
        root / TOOL_RELATIVE / "server-config.py", "ONE_TIME_MIGRATION_SEEDS"
    )
    for key, value in defaults.items():
        values.setdefault(str(key), set()).add(str(value))
    daytona = (root / "deployment/steps/60-daytona.sh").read_text()
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
    for name, row in sorted(packages.items()):
        path = f"npmPackages.{name}"
        if not isinstance(row, dict):
            add(findings, "npm_package_invalid", path, "entry must be an object")
            continue
        version = str(row.get("version") or "")
        if not version or version in {"latest", "next", "main", "master", "*"}:
            add(findings, "npm_version_floating", path, version)
        integrity = str(row.get("integrity") or "")
        match = SRI.fullmatch(integrity)
        try:
            decoded = base64.b64decode(match.group(1), validate=True) if match else b""
        except ValueError:
            decoded = b""
        if len(decoded) != 64:
            add(findings, "npm_integrity_invalid", path, integrity)
        version_key = row.get("versionKey")
        if version_key and version not in versions.get(str(version_key), set()):
            add(
                findings,
                "npm_version_declaration_drift",
                path,
                f"{version_key} does not declare {version}",
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
            if install_name not in text:
                add(
                    findings,
                    "npm_install_declaration_missing",
                    str(install_path),
                    install_name,
                )

    for relative in lock.get("npmLockfiles") or []:
        path = root / str(relative)
        try:
            document = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            add(findings, "npm_lock_invalid", str(relative), str(exc))
            continue
        if document.get("lockfileVersion") != 3:
            add(
                findings,
                "npm_lock_version_invalid",
                str(relative),
                str(document.get("lockfileVersion")),
            )
        lock_packages = document.get("packages") or {}
        if not isinstance(lock_packages, dict):
            add(
                findings,
                "npm_lock_packages_invalid",
                str(relative),
                "packages must be an object",
            )
            continue
        for package_path, package in lock_packages.items():
            if not package_path:
                continue
            if not isinstance(package, dict) or not package.get("version"):
                add(
                    findings,
                    "npm_lock_package_unversioned",
                    str(relative),
                    package_path,
                )
            if package.get("resolved") and not package.get("integrity"):
                add(
                    findings, "npm_lock_package_unverified", str(relative), package_path
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
        paths = row.get("paths") or []
        if not isinstance(paths, list) or not paths:
            add(findings, "download_consumers_missing", path, "paths must be non-empty")
            continue
        texts: list[str] = []
        for relative in paths:
            consumer_paths.add(str(relative))
            try:
                texts.append((root / str(relative)).read_text())
            except OSError as exc:
                add(findings, "download_consumer_invalid", str(relative), str(exc))
        joined = "\n".join(texts)
        if not SHA256.fullmatch(digest) or digest not in joined:
            add(findings, "download_checksum_not_enforced", path, digest)
        filename = url.rsplit("/", 1)[-1]
        version_match = re.search(r"(?:^|/)(v?[0-9]+\.[0-9]+\.[0-9]+)(?:/|_)", url)
        identity_tokens = [filename]
        if version_match:
            identity_tokens.append(version_match.group(1).lstrip("v"))
        if not all(token in joined for token in identity_tokens):
            add(
                findings,
                "download_identity_not_declared",
                path,
                ", ".join(identity_tokens),
            )

    executable_download_sources = {
        "deployment/steps/10-host.sh",
        "deployment/steps/60-daytona.sh",
        "tools/platform-cli/server-toolhive.py",
    }
    for relative in sorted(executable_download_sources - consumer_paths):
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
        for key in ("keyUrl", "repositoryUrl", "signedBy"):
            value = str(row.get(key) or "")
            if not value or value not in text:
                add(
                    findings,
                    "signed_repository_contract_drift",
                    path,
                    f"{key}={value!r}",
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


def executable_sources(root: Path) -> list[Path]:
    result: list[Path] = []
    for directory in (root / TOOL_RELATIVE, root / "deployment/steps"):
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
        if re.search(r"\bnpm\s+(?:install|i)\b|\bnpx\s+--yes\b", text):
            result.add(str(path.relative_to(root)))
    return result


def validate(root: Path = ROOT, lock_path: Path | None = None) -> list[dict[str, str]]:
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
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args(argv)
    findings = validate(args.root.resolve(), args.lock.resolve() if args.lock else None)
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
