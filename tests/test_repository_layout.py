from __future__ import annotations

import re
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROOT_MARKDOWN_ALLOWLIST = {"README.md"}
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
EXTERNAL_SCHEMES = {"data", "http", "https", "mailto"}
CANONICAL_CONTRACTS = {
    "config/platform.yaml",
    "config/platform.lock.yaml",
    "config/connections.yaml",
    "config/dependencies.lock.json",
    "config/compose-seeds.lock.json",
    "config/platform.env.example",
    "config/profiles/catalog.yaml",
    "deployment/services/kestra/application.yaml",
    "deployment/services/searxng/settings.yml",
    "deployment/services/hermes/service.unit",
    "deployment/services/hermes/config.yaml.template",
    "deployment/services/hermes/soul.txt",
    "deployment/services/hermes/platform-skill.txt",
    "deployment/services/hermes/acceptance-canary.py",
    "deployment/services/hermes/bootstrap-mattermost.py",
    "deployment/steps/10-host.sh",
    "deployment/steps/50-paperclip.sh",
    "deployment/steps/60-daytona.sh",
    "deployment/steps/90-cloudflare-tunnel.sh",
    "deployment/steps/91-origin-firewall.sh",
}
LEGACY_STATIC_PATHS = {
    "platform.yaml",
    "platform.lock.yaml",
    "connections.yaml",
    "dependencies.lock.json",
    "deploy",
    "deployment/compose",
    "deployment/systemd",
    "config/services",
    "hermes",
    "kestra",
    "profiles/profiles.yaml",
    "patches",
}
CANONICAL_DEPLOYMENT_STEPS = {
    "10-host.sh",
    "50-paperclip.sh",
    "60-daytona.sh",
    "90-cloudflare-tunnel.sh",
    "91-origin-firewall.sh",
}


def documentation_files() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]


class RepositoryLayoutTests(unittest.TestCase):
    def test_python_tooling_is_owned_by_tools_directory(self) -> None:
        self.assertFalse((ROOT / "scripts").exists())
        self.assertFalse((ROOT / "pyproject.toml").exists())
        self.assertFalse((ROOT / "evidence").exists())
        self.assertTrue((ROOT / "tools/platform-cli/platform.py").is_file())
        self.assertTrue((ROOT / "tools/platform-cli/pyproject.toml").is_file())

    def test_root_contains_only_the_documentation_entrypoint(self) -> None:
        root_markdown = {path.name for path in ROOT.glob("*.md")}
        self.assertEqual(root_markdown, ROOT_MARKDOWN_ALLOWLIST)

    def test_internal_documentation_links_resolve(self) -> None:
        broken: list[str] = []
        for document in documentation_files():
            for raw_target in MARKDOWN_LINK.findall(document.read_text()):
                target = raw_target.strip().strip("<>")
                parsed = urlsplit(target)
                if parsed.scheme in EXTERNAL_SCHEMES or not parsed.path:
                    continue
                linked_path = (document.parent / unquote(parsed.path)).resolve()
                if not linked_path.exists():
                    broken.append(f"{document.relative_to(ROOT)} -> {target}")

        self.assertEqual(broken, [], "Broken internal documentation links")

    def test_canonical_contracts_replace_legacy_static_paths(self) -> None:
        missing = sorted(
            relative
            for relative in CANONICAL_CONTRACTS
            if not (ROOT / relative).is_file()
        )
        legacy = sorted(
            relative for relative in LEGACY_STATIC_PATHS if (ROOT / relative).exists()
        )

        self.assertEqual(missing, [], "Missing canonical contracts")
        self.assertEqual(legacy, [], "Legacy static paths remain")

    def test_manifest_owns_every_canonical_compose_file(self) -> None:
        manifest = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        declared = {
            component["compose"]
            for component in manifest["spec"]["components"]
            if "compose" in component
        }
        actual = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "deployment/services").glob("*/compose.yaml")
        }

        self.assertEqual(declared, actual)
        self.assertEqual(len(actual), 16)
        self.assertTrue(
            all(
                path.startswith("deployment/services/")
                and path.endswith("/compose.yaml")
                for path in declared
            )
        )

    def test_compose_mounts_canonical_service_assets(self) -> None:
        kestra = yaml.safe_load(
            (ROOT / "deployment/services/kestra/compose.yaml").read_text()
        )
        kestra_command = kestra["services"]["kestra"]["command"]
        kestra_volumes = kestra["services"]["kestra"]["volumes"]
        self.assertIn(
            "/opt/mte-platform/config/services/kestra/application.yaml:"
            "/etc/kestra/application.yaml:ro",
            kestra_volumes,
        )
        self.assertNotIn("--flow-path", kestra_command)
        self.assertNotIn("/app/flows", kestra_command)
        self.assertFalse(
            any("workflows/kestra" in volume for volume in kestra_volumes),
            "Kestra workflows must be reconciled through the REST API, not mounted",
        )

        searxng = yaml.safe_load(
            (ROOT / "deployment/services/searxng/compose.yaml").read_text()
        )
        self.assertIn(
            "/opt/mte-platform/config/services/searxng/settings.yml:"
            "/template/settings.yml:ro",
            searxng["services"]["config-init"]["volumes"],
        )

    def test_runtime_installers_are_exact_numbered_deployment_steps(self) -> None:
        steps = ROOT / "deployment/steps"
        actual = {path.name for path in steps.iterdir() if path.is_file()}
        self.assertEqual(actual, CANONICAL_DEPLOYMENT_STEPS)
        for name in actual:
            path = steps / name
            with self.subTest(name=name):
                self.assertTrue(path.read_text().startswith("#!/usr/bin/env bash\n"))
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
