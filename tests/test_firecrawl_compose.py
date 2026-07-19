import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deployment/services/firecrawl/compose.yaml"


class FirecrawlComposeTests(unittest.TestCase):
    def test_api_exposes_only_an_internal_alias_to_toolhive_runtime(self):
        compose = yaml.safe_load(COMPOSE.read_text())
        api = compose["services"]["api"]

        self.assertEqual(api["networks"]["tool-runtime"]["aliases"], ["firecrawl-api"])
        self.assertEqual(
            compose["networks"]["tool-runtime"],
            {
                "name": "${MTE_TOOL_RUNTIME_NETWORK:?required}",
                "external": True,
            },
        )
        self.assertNotIn("tool-runtime", compose["services"]["redis"]["networks"])
        self.assertNotIn(
            "tool-runtime", compose["services"]["nuq-postgres"]["networks"]
        )
        self.assertNotIn("tool-control", api["networks"])
        self.assertFalse(
            any("docker.sock" in volume for volume in api.get("volumes", []))
        )

    def test_valkey_runtime_secret_is_not_a_compose_or_process_argument(self):
        compose = yaml.safe_load(COMPOSE.read_text())
        redis = compose["services"]["redis"]
        command = redis["command"]

        self.assertEqual(command[:2], ["/bin/sh", "-euc"])
        self.assertFalse(any("${FIRECRAWL_REDIS_PASSWORD" in part for part in command))
        self.assertNotIn("--requirepass", command)
        self.assertIn("$(printenv FIRECRAWL_REDIS_PASSWORD)", command[2])
        self.assertIn("umask 077", command[2])
        self.assertIn("unset FIRECRAWL_REDIS_PASSWORD", command[2])
        self.assertIn("exec valkey-server /tmp/mte-firecrawl-redis.conf", command[2])
        self.assertEqual(redis["user"], "999:1000")
        self.assertEqual(
            redis["tmpfs"],
            ["/tmp:rw,noexec,nosuid,nodev,mode=1777"],
        )

        health = " ".join(redis["healthcheck"]["test"])
        self.assertIn("VALKEYCLI_AUTH=", health)
        self.assertNotIn("valkey-cli -a", health)

    def test_valkey_pin_preserves_protocol_hostname_and_isolates_legacy_data(self):
        compose = yaml.safe_load(COMPOSE.read_text())
        datastore = compose["services"]["redis"]

        self.assertEqual(
            datastore["image"], "${MTE_FIRECRAWL_VALKEY_IMAGE:?required}"
        )
        self.assertEqual(
            compose["volumes"]["firecrawl-valkey"]["name"], "mte-firecrawl-valkey"
        )
        self.assertEqual(datastore["volumes"], ["firecrawl-valkey:/data"])
        self.assertNotIn("firecrawl-redis", compose["volumes"])
        self.assertEqual(
            compose["services"]["api"]["depends_on"]["redis"]["condition"],
            "service_healthy",
        )
        self.assertEqual(
            compose["services"]["api"]["environment"]["REDIS_URL"],
            "${FIRECRAWL_REDIS_URL:?required}",
        )

    def test_final_manifest_contains_runtime_secret_hardening(self):
        raw = COMPOSE.read_text()
        self.assertNotIn("redis-server\n    - --requirepass", raw)
        self.assertNotIn("redis-cli -a", raw)
        self.assertIn("VALKEYCLI_AUTH=", raw)
        self.assertNotIn("image: ${MTE_FIRECRAWL_REDIS_IMAGE", raw)
        self.assertIn("unset FIRECRAWL_REDIS_PASSWORD", raw)

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is required")
    def test_compose_render_does_not_materialize_password_in_command(self):
        password = "firecrawl-render-test-not-a-secret"
        source = yaml.safe_load(COMPOSE.read_text())
        redis = source["services"]["redis"]
        minimal = {
            "services": {
                "redis": {
                    "image": (
                        "valkey/valkey:9.1.0-alpine@sha256:"
                        "c9b77919daeba2c02ad954d0c844cc4e7142069d177b89c5fd771f405daf9e02"
                    ),
                    "user": redis["user"],
                    "environment": redis["environment"],
                    "command": redis["command"],
                    "tmpfs": redis["tmpfs"],
                    "healthcheck": redis["healthcheck"],
                }
            }
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            compose_path = root / "compose.yaml"
            env_path = root / "platform.env"
            compose_path.write_text(yaml.safe_dump(minimal, sort_keys=False))
            env_path.write_text(
                f"FIRECRAWL_REDIS_PASSWORD={password}\n"
                "MTE_HEALTHCHECK_FAST_INTERVAL=10s\n"
                "MTE_HEALTHCHECK_FAST_TIMEOUT=5s\n"
                "MTE_HEALTHCHECK_FAST_RETRIES=15\n"
            )
            result = subprocess.run(
                [
                    "docker",
                    "compose",
                    "--env-file",
                    str(env_path),
                    "-f",
                    str(compose_path),
                    "config",
                    "--format",
                    "json",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
        rendered = json.loads(result.stdout)["services"]["redis"]
        rendered_command = " ".join(rendered["command"])
        self.assertNotIn(password, rendered_command)
        self.assertNotIn("${FIRECRAWL_REDIS_PASSWORD:?required}", rendered_command)
        self.assertIn("$(printenv FIRECRAWL_REDIS_PASSWORD)", rendered_command)
        health = " ".join(rendered["healthcheck"]["test"])
        self.assertNotIn(password, health)
        self.assertIn("${FIRECRAWL_REDIS_PASSWORD:?required}", health)


if __name__ == "__main__":
    unittest.main()
