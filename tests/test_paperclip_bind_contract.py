from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PaperclipPrivateBindContractTests(unittest.TestCase):
    def test_lan_private_route_uses_authenticated_mode(self):
        config = load("paperclip_bind_server_config", "tools/platform-cli/server-config.py")
        runtime = (ROOT / "deployment/steps/paperclip.sh").read_text()

        self.assertEqual(
            config.ONE_TIME_MIGRATION_SEEDS["PAPERCLIP_DEPLOYMENT_MODE"],
            "authenticated",
        )
        self.assertEqual(
            config.ONE_TIME_MIGRATION_SEEDS["PAPERCLIP_DEPLOYMENT_EXPOSURE"],
            "private",
        )
        self.assertEqual(
            config.REVIEWED_CANONICAL_VALUE_MIGRATIONS[
                "PAPERCLIP_DEPLOYMENT_MODE"
            ],
            ("local_trusted", "authenticated"),
        )
        self.assertIn('-e PAPERCLIP_BIND=lan', runtime)
        self.assertIn('-e PAPERCLIP_HOME=/data', runtime)
        self.assertIn('bind: "lan",', runtime)
        self.assertIn('host: "0.0.0.0",', runtime)

    def test_authenticated_private_mode_generates_and_preserves_agent_secret(self):
        config = load("paperclip_bind_secret_config", "tools/platform-cli/server-config.py")
        platform = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        paperclip = next(
            component
            for component in platform["spec"]["components"]
            if component["id"] == "paperclip"
        )

        self.assertIn("PAPERCLIP_AGENT_JWT_SECRET", paperclip["secrets"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "secrets/platform.env"
            config_source = root / "templates/platform.json"
            compose_seed_source = root / "templates/compose-seeds.lock.json"
            config_source.parent.mkdir(parents=True)
            config_source.write_text(
                '{"spec":{"components":[{"id":"paperclip","secrets":'
                '["PAPERCLIP_AGENT_JWT_SECRET"]}]}}\n'
            )
            compose_seed_source.write_text(
                '{"apiVersion":"micro-task-engine/v1alpha1",'
                '"kind":"ComposeSeedCatalog",'
                '"metadata":{"contractVersion":1},"seeds":{}}\n'
            )
            replacements = {
                "ROOT": root,
                "SECRET_ROOT": canonical.parent,
                "SOURCE": canonical,
                "LOCK": canonical.parent / ".platform-env.lock",
                "CONFIG_SOURCE": config_source,
                "COMPOSE_SEED_SOURCE": compose_seed_source,
                "PROFILE_SOURCE": root / "templates/profiles/missing.yaml",
                "ONE_TIME_MIGRATION_SEEDS": {
                    **config.ONE_TIME_MIGRATION_SEEDS,
                    "DATA_CONTENT_PROFILE": "none",
                },
                "REVIEWED_CANONICAL_VALUE_MIGRATIONS": {
                    "PAPERCLIP_DEPLOYMENT_MODE": (
                        "local_trusted",
                        "authenticated",
                    )
                },
            }
            with mock.patch.multiple(config, **replacements):
                clean = config.init_source({})
                values = config.parse_env(canonical)
                self.assertIn("PAPERCLIP_AGENT_JWT_SECRET", clean["createdKeys"])
                self.assertGreaterEqual(
                    len(values["PAPERCLIP_AGENT_JWT_SECRET"]), 32
                )
                values["PAPERCLIP_DEPLOYMENT_MODE"] = "local_trusted"
                values.pop("PAPERCLIP_AGENT_JWT_SECRET")
                config.write_env(canonical, values)

                original_stat = Path.stat

                def root_owned_stat(path, *args, **kwargs):
                    result = original_stat(path, *args, **kwargs)
                    if Path(path) != canonical:
                        return result
                    fields = list(result)
                    fields[4] = 0
                    return os.stat_result(fields)

                with mock.patch.object(Path, "stat", root_owned_stat):
                    migrated = config.init_source({})
                    preserved = config.parse_env(canonical)[
                        "PAPERCLIP_AGENT_JWT_SECRET"
                    ]
                    repeated = config.init_source({})

                self.assertIn(
                    "PAPERCLIP_AGENT_JWT_SECRET", migrated["createdKeys"]
                )
                self.assertIn(
                    "PAPERCLIP_DEPLOYMENT_MODE", migrated["migratedKeys"]
                )
                self.assertEqual(
                    config.parse_env(canonical)["PAPERCLIP_DEPLOYMENT_MODE"],
                    "authenticated",
                )
                self.assertNotIn(
                    "PAPERCLIP_AGENT_JWT_SECRET", repeated["createdKeys"]
                )
                self.assertEqual(
                    config.parse_env(canonical)["PAPERCLIP_AGENT_JWT_SECRET"],
                    preserved,
                )

    def test_render_materializes_missing_renderer_owned_agent_secret(self):
        config = load("paperclip_bind_render_config", "tools/platform-cli/server-config.py")
        with tempfile.TemporaryDirectory() as temporary:
            canonical = Path(temporary) / "secrets/platform.env"
            replacements = {
                "SECRET_ROOT": canonical.parent,
                "SOURCE": canonical,
                "LOCK": canonical.parent / ".platform-env.lock",
            }
            with mock.patch.multiple(config, **replacements):
                config.write_env(canonical, {})
                original_stat = Path.stat

                def root_owned_stat(path, *args, **kwargs):
                    result = original_stat(path, *args, **kwargs)
                    if Path(path) != canonical:
                        return result
                    fields = list(result)
                    fields[4] = 0
                    return os.stat_result(fields)

                with (
                    mock.patch.object(Path, "stat", root_owned_stat),
                    mock.patch.object(config, "platform_lock_object", return_value={}),
                    mock.patch.object(
                        config,
                        "config_object",
                        return_value={"spec": {"components": []}},
                    ),
                    mock.patch.object(
                        config,
                        "active_config_object",
                        side_effect=lambda cfg, *_: cfg,
                    ),
                    mock.patch.object(
                        config,
                        "declared_keys",
                        return_value=(
                            {"PAPERCLIP_AGENT_JWT_SECRET"},
                            {},
                            {},
                        ),
                    ),
                    mock.patch.object(
                        config,
                        "resolved_projection_values",
                        side_effect=RuntimeError("render-reached-projections"),
                    ),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "render-reached-projections"
                    ):
                        config.render()

            values = config.parse_env(canonical)
            self.assertGreaterEqual(len(values["PAPERCLIP_AGENT_JWT_SECRET"]), 32)


if __name__ == "__main__":
    unittest.main()
