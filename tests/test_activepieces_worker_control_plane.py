from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deployment/services/activepieces/compose.yaml"


def load_server_config():
    spec = importlib.util.spec_from_file_location(
        "mte_server_config_activepieces_worker_test",
        ROOT / "tools/platform-cli/server-config.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ActivepiecesWorkerControlPlaneTests(unittest.TestCase):
    def test_worker_uses_internal_control_plane_and_app_keeps_public_url(self):
        compose = yaml.safe_load(
            COMPOSE.read_text()
        )
        app = compose["services"]["app"]
        worker = compose["services"]["worker"]

        self.assertEqual(
            app["environment"]["AP_FRONTEND_URL"],
            "${AP_FRONTEND_URL:?required}",
        )
        self.assertEqual(
            worker["environment"]["AP_FRONTEND_URL"],
            "${MTE_ACTIVEPIECES_WORKER_ENV_AP_FRONTEND_URL:?required}",
        )
        self.assertIn(
            "mte-activepieces-app",
            app["networks"]["activepieces-data"]["aliases"],
        )
        self.assertIn("activepieces-data", worker["networks"])
        self.assertEqual(
            app["networks"]["tool-runtime"]["aliases"], ["activepieces"]
        )
        self.assertEqual(
            compose["networks"]["tool-runtime"],
            {"name": "mte-tool-runtime", "external": True},
        )
        self.assertNotIn("tool-runtime", worker["networks"])

    def test_internal_worker_url_is_reviewed_fill_only_ssot_seed(self):
        key = "MTE_ACTIVEPIECES_WORKER_ENV_AP_FRONTEND_URL"
        catalog = json.loads((ROOT / "config/compose-seeds.lock.json").read_text())[
            "seeds"
        ]
        server_config = load_server_config()

        self.assertEqual(catalog[key], "http://mte-activepieces-app:80")
        self.assertEqual(
            server_config.REVIEWED_ACTIVEPIECES_COMPOSE_SEED_MIGRATIONS,
            {key},
        )
        # Generated implementation-level defaults belong to the reviewed seed
        # catalog and are materialized into the canonical server-side env. The
        # public template documents only operator-owned inputs.
        self.assertNotIn(
            f"{key}=",
            (ROOT / "config/platform.env.example").read_text().splitlines(),
        )

    def test_final_manifest_contains_the_control_plane_contract(self):
        source = COMPOSE.read_text()
        self.assertIn("mte-activepieces-app", source)
        self.assertIn("MTE_ACTIVEPIECES_WORKER_ENV_AP_FRONTEND_URL", source)
        self.assertNotIn(
            "AP_FRONTEND_URL: ${MTE_ACTIVEPIECES_WORKER_ENV_AP_FRONTEND_URL:?required}\n      AP_ENCRYPTION_KEY",
            source.split("worker:", 1)[0],
        )


if __name__ == "__main__":
    unittest.main()
