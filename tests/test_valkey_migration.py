from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
DAYTONA_STEP = ROOT / "deployment/steps/daytona.sh"
DAYTONA_COMPOSE = ROOT / "deployment/services/daytona/compose.yaml"
FIRECRAWL_COMPOSE = ROOT / "deployment/services/firecrawl/compose.yaml"
COMPOSE_SEEDS = ROOT / "config/compose-seeds.lock.json"
DEPENDENCY_LOCK = ROOT / "config/dependencies.lock.json"
VALKEY_REF = (
    "valkey/valkey:9.1.0-alpine@sha256:"
    "c9b77919daeba2c02ad954d0c844cc4e7142069d177b89c5fd771f405daf9e02"
)


class ValkeyMigrationContractTests(unittest.TestCase):
    def test_firecrawl_and_daytona_share_the_reviewed_immutable_valkey_pin(self):
        seeds = json.loads(COMPOSE_SEEDS.read_text())["seeds"]
        lock = json.loads(DEPENDENCY_LOCK.read_text())["runtimeImages"]

        self.assertEqual(seeds["MTE_FIRECRAWL_VALKEY_IMAGE"], VALKEY_REF)
        self.assertEqual(lock["MTE_DAYTONA_VALKEY_IMAGE"]["ref"], VALKEY_REF)
        self.assertNotIn("MTE_FIRECRAWL_REDIS_IMAGE", seeds)
        self.assertNotIn("MTE_DAYTONA_REDIS_IMAGE", lock)

    def test_firecrawl_keeps_protocol_but_never_mounts_incompatible_legacy_volume(self):
        compose = yaml.safe_load(FIRECRAWL_COMPOSE.read_text())
        datastore = compose["services"]["redis"]
        script = datastore["command"][2]
        health = " ".join(datastore["healthcheck"]["test"])

        self.assertEqual(
            datastore["image"], "${MTE_FIRECRAWL_VALKEY_IMAGE:?required}"
        )
        self.assertIn("valkey-server", script)
        self.assertIn("valkey-cli", health)
        self.assertEqual(datastore["volumes"], ["firecrawl-valkey:/data"])
        self.assertEqual(
            compose["volumes"]["firecrawl-valkey"]["name"], "mte-firecrawl-valkey"
        )
        self.assertNotIn("firecrawl-redis", compose["volumes"])
        self.assertIn("REDIS_URL", compose["services"]["api"]["environment"])

    def test_daytona_compose_has_healthcheck_and_persistent_valkey_volume(self):
        compose = yaml.safe_load(DAYTONA_COMPOSE.read_text())
        datastore = compose["services"]["redis"]

        self.assertEqual(
            datastore["image"], "${MTE_DAYTONA_VALKEY_IMAGE:?required}"
        )
        self.assertEqual(datastore["command"][0], "valkey-server")
        self.assertEqual(
            datastore["healthcheck"]["test"], ["CMD", "valkey-cli", "ping"]
        )
        self.assertEqual(datastore["volumes"], ["daytona-valkey:/data"])
        self.assertEqual(
            compose["volumes"]["daytona-valkey"]["name"], "mte-daytona-valkey"
        )
        self.assertNotIn("MTE_DAYTONA_REDIS_IMAGE", DAYTONA_COMPOSE.read_text())

    def test_daytona_deployment_reuses_volume_and_never_deletes_data(self):
        source = DAYTONA_STEP.read_text()
        install = source[
            source.index("install_daytona() {") : source.index("\nprovision_key() {")
        ]
        remove_start = source.index("remove() {")
        remove = source[remove_start : source.index("acceptance()", remove_start)]

        self.assertIn(
            "COMPOSE=$RELEASE_ROOT/deployment/services/daytona/compose.yaml", source
        )
        self.assertIn("compose up -d", install)
        self.assertNotIn("compose down", install)
        self.assertNotIn("migrate_daytona_valkey_volume", source)
        self.assertNotIn("docker volume rm", source)
        self.assertNotIn("docker volume prune", source)

        absent = subprocess.run(
            [
                "bash",
                "-ceu",
                "compose() { printf '%s\\n' \"$*\"; }; "
                "die() { printf '%s\\n' \"$*\" >&2; exit 2; }; "
                "log() { :; }; "
                f"{remove}\nremove",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(absent.returncode, 0)
        self.assertEqual(absent.stdout.splitlines(), ["down"])

        failed = subprocess.run(
            [
                "bash",
                "-ceu",
                "compose() { printf '%s\\n' \"$*\"; return 41; }; "
                "die() { printf '%s\\n' \"$*\" >&2; exit 2; }; "
                "log() { :; }; "
                f"{remove}\nremove",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(failed.stdout.splitlines(), ["down"])
        self.assertIn("container removal failed", failed.stderr)

    def test_daytona_dex_config_is_readable_by_upstream_unprivileged_dex(self):
        source = DAYTONA_STEP.read_text()

        self.assertIn("dex_path.chmod(0o644)", source)
        self.assertNotIn("dex_path.chmod(0o600)", source)

    def test_daytona_api_key_guard_uses_the_same_config_sources_as_snapshot(self):
        source = DAYTONA_STEP.read_text()

        self.assertIn('config_hash "$ENV_FILE" "$DAYTONA_ENV_FILE"', source)

    def test_daytona_skill_contract_uses_the_catalog_profile_ref_field(self):
        source = DAYTONA_STEP.read_text()

        self.assertIn('str(profile.get("ref")): profile', source)
        self.assertNotIn('str(profile.get("profileRef")): profile', source)

    def test_daytona_uses_the_immutable_paperclip_image_for_its_sdk(self):
        source = DAYTONA_STEP.read_text()

        self.assertEqual(source.count('env_value "$ENV_FILE" MTE_PAPERCLIP_IMAGE'), 2)
        self.assertEqual(source.count('import("@daytonaio/sdk")'), 2)
        self.assertNotIn("paperclip-tools", source)

    def test_daytona_snapshot_client_uses_the_private_control_plane_network(self):
        source = DAYTONA_STEP.read_text()

        self.assertEqual(
            source.count('docker run --rm -i --network "$daytona_network" --user 0:0'),
            2,
        )
        self.assertEqual(source.count('safe("MTE_DAYTONA_INTERNAL_API_URL")'), 1)
        self.assertIn('apiUrl:values.MTE_DAYTONA_INTERNAL_API_URL', source)
        self.assertEqual(
            source.count('-v "$RUNTIME_ENV:/run/secrets/platform.env:ro"'), 2
        )
        self.assertNotIn('docker run --rm -i --network host --user 0:0', source)

    def test_daytona_build_initializes_its_required_minio_bucket_idempotently(self):
        source = DAYTONA_STEP.read_text()

        self.assertIn("CreateBucketCommand", source)
        self.assertIn("HeadBucketCommand", source)
        self.assertIn('Bucket: "daytona"', source)
        self.assertIn('endpoint: safe("MTE_DAYTONA_MINIO_ENDPOINT_URL")', source)
        self.assertIn('require("@aws-sdk/client-s3")', source)

    def test_daytona_snapshot_build_uses_api_polling_not_the_host_only_log_proxy(self):
        source = DAYTONA_STEP.read_text()

        self.assertIn("{timeout:1800}", source)
        self.assertNotIn("onLogs:", source)


if __name__ == "__main__":
    unittest.main()
