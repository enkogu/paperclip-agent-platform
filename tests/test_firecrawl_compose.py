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
    def test_redis_runtime_secret_is_not_a_compose_or_process_argument(self):
        compose = yaml.safe_load(COMPOSE.read_text())
        redis = compose["services"]["redis"]
        command = redis["command"]

        self.assertEqual(command[:2], ["/bin/sh", "-euc"])
        self.assertFalse(any("${FIRECRAWL_REDIS_PASSWORD" in part for part in command))
        self.assertNotIn("--requirepass", command)
        self.assertIn("$(printenv FIRECRAWL_REDIS_PASSWORD)", command[2])
        self.assertIn("umask 077", command[2])
        self.assertIn("unset FIRECRAWL_REDIS_PASSWORD", command[2])
        self.assertIn("exec redis-server /tmp/mte-firecrawl-redis.conf", command[2])
        self.assertEqual(redis["user"], "redis")
        self.assertEqual(
            redis["tmpfs"],
            ["/tmp:rw,noexec,nosuid,nodev,mode=1777"],
        )

        health = " ".join(redis["healthcheck"]["test"])
        self.assertIn("REDISCLI_AUTH=", health)
        self.assertNotIn("redis-cli -a", health)

    def test_final_manifest_contains_runtime_secret_hardening(self):
        raw = COMPOSE.read_text()
        self.assertNotIn("redis-server\n    - --requirepass", raw)
        self.assertNotIn("redis-cli -a", raw)
        self.assertIn("REDISCLI_AUTH=", raw)
        self.assertIn("unset FIRECRAWL_REDIS_PASSWORD", raw)

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is required")
    def test_compose_render_does_not_materialize_password_in_command(self):
        password = "firecrawl-render-test-not-a-secret"
        source = yaml.safe_load(COMPOSE.read_text())
        redis = source["services"]["redis"]
        minimal = {
            "services": {
                "redis": {
                    "image": "redis:7.4-alpine",
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
            env_path.write_text(f"FIRECRAWL_REDIS_PASSWORD={password}\n")
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
