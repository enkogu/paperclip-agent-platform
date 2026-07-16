from __future__ import annotations

import importlib.util
import ipaddress
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicPortabilityTests(unittest.TestCase):
    def test_config_init_requires_explicit_operator_identity(self) -> None:
        config = load(ROOT / "tools/platform-cli/server-config.py", "portability_server_config")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "platform.env"
            with (
                mock.patch.object(config, "SOURCE", source),
                mock.patch.object(config, "config_object", return_value={}),
                mock.patch.object(config, "active_config_object", return_value={}),
                mock.patch.object(
                    config,
                    "declared_keys",
                    return_value=(
                        set(config.REQUIRED_OPERATOR_BOOTSTRAP_KEYS),
                        {},
                        {},
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    config.ConfigError, "explicit operator bootstrap input"
                ):
                    config.init_source({})

    def test_cloudflare_clis_require_an_explicit_environment_file(self) -> None:
        scripts = (
            "render-cloudflare.py",
            "cloudflare-preflight.py",
            "cloudflare-inventory.py",
            "cloudflare-token-bootstrap.py",
        )
        for script in scripts:
            with self.subTest(script=script):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "tools/platform-cli" / script)],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("--env-file", result.stderr)
                self.assertIn("required", result.stderr)

    def test_documented_bootstrap_addresses_are_non_routable_examples(self) -> None:
        values = {}
        for raw in (ROOT / "config/platform.env.example").read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        target_address = values["MTE_SSH_TARGET"].split("@", 1)[1]
        for key in ("MTE_EXCLUDED_HOST_1", "MTE_EXCLUDED_HOST_2"):
            self.assertFalse(ipaddress.ip_address(values[key]).is_global)
        self.assertFalse(ipaddress.ip_address(target_address).is_global)
        self.assertTrue(values["PLATFORM_BASE_DOMAIN"].endswith(".example.com"))

    def test_repository_has_one_compact_environment_template(self) -> None:
        templates = sorted(
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file()
            and (
                path.name.endswith(".env.example") or path.name.endswith(".example.env")
            )
        )
        self.assertEqual(templates, ["config/platform.env.example"])
        lines = (ROOT / templates[0]).read_text().splitlines()
        self.assertLess(len(lines), 80)
        self.assertIn("/root/.config/mte-secrets/platform.env", "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
