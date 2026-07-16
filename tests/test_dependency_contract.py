from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_dependencies", ROOT / "tools/platform-cli/validate-dependencies.py"
)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class DependencyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads(
            (ROOT / "config/dependencies.lock.json").read_text()
        )

    def test_repository_dependency_contract_is_clean(self) -> None:
        self.assertEqual(module.validate(ROOT), [])

    def test_floating_compose_seed_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "config",
                "deployment/services",
                "deployment/steps",
                "tools/platform-cli",
            ):
                (root / relative).mkdir(parents=True, exist_ok=True)
            for source in (ROOT / "deployment/services").glob("*/compose.yaml"):
                destination = (
                    root
                    / "deployment/services"
                    / source.parent.name
                    / "compose.yaml"
                )
                destination.parent.mkdir(parents=True)
                shutil.copy2(source, destination)
            shutil.copy2(
                ROOT / "config/compose-seeds.lock.json",
                root / "config/compose-seeds.lock.json",
            )
            for relative in (
                "tools/platform-cli/server-config.py",
                "deployment/steps/60-daytona.sh",
                "deployment/steps/90-cloudflare-tunnel.sh",
            ):
                shutil.copy2(ROOT / relative, root / relative)
            catalog_path = root / "config/compose-seeds.lock.json"
            catalog = json.loads(catalog_path.read_text())
            catalog["seeds"]["MTE_SEARXNG_VALKEY_IMAGE"] = "valkey/valkey:latest"
            catalog_path.write_text(json.dumps(catalog))
            findings: list[dict[str, str]] = []
            module.validate_images(root, self.lock, findings)
            self.assertIn(
                "compose_seed_image_not_digest_pinned",
                {finding["code"] for finding in findings},
            )

    def test_only_active_deployment_compose_files_are_scanned(self) -> None:
        self.assertEqual(
            self.lock["imageSources"]["directComposeGlobs"],
            ["deployment/services/*/compose.yaml"],
        )

    def test_floating_runtime_image_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["runtimeImages"]["MTE_DAYTONA_API_IMAGE"]["ref"] = (
            "daytonaio/daytona-api:latest"
        )
        findings: list[dict[str, str]] = []
        module.validate_images(ROOT, lock, findings)
        self.assertIn("image_not_digest_pinned", {row["code"] for row in findings})

    def test_download_without_checksum_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["downloads"]["toolhive-linux-amd64"]["sha256"] = ""
        findings: list[dict[str, str]] = []
        module.validate_downloads(ROOT, lock, findings)
        codes = {row["code"] for row in findings}
        self.assertIn("download_sha256_invalid", codes)
        self.assertIn("download_checksum_not_enforced", codes)

    def test_unlisted_network_fetch_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "tools/platform-cli/rogue.sh"
            script.parent.mkdir(parents=True)
            script.write_text(
                "#!/bin/sh\ncurl -fsSL https://example.invalid/tool -o /tmp/tool\n"
            )
            self.assertEqual(
                module.discover_network_fetch_sources(root), {"tools/platform-cli/rogue.sh"}
            )

    def test_floating_npm_version_is_rejected(self) -> None:
        lock = copy.deepcopy(self.lock)
        lock["npmPackages"]["paperclipai"]["version"] = "latest"
        findings: list[dict[str, str]] = []
        module.validate_npm(ROOT, lock, findings)
        self.assertIn("npm_version_floating", {row["code"] for row in findings})


if __name__ == "__main__":
    unittest.main()
