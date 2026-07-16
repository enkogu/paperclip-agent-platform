import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SERVICES_DIR = ROOT / "deployment/services"

SENSITIVE_NAME = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ENCRYPT|JWT|SALT|"
    r"COOKIE|CREDENTIAL|AUTH|WEBHOOK|CONNECTION_STRING)"
)
COMPOSE_PLACEHOLDER = re.compile(r"(?<!\$)\$\{(?P<name>[A-Z][A-Z0-9_]*)(?::[^}]*)?\}")

RUNTIMES = {
    "activepieces-data.yaml": {
        "service": "redis",
        "password": "AP_REDIS_PASSWORD",
        "cli_auth": "REDISCLI_AUTH",
        "exec": "redis-server",
        "config": "/run/mte-activepieces-redis/redis.conf",
        "secret_file": "/run/mte-activepieces-redis/redis.password",
        "secret_mode": "0400",
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": (
            "/run/mte-activepieces-redis:rw,noexec,nosuid,nodev,"
            "mode=0700,uid=999,gid=1000"
        ),
        "old_command": [
            "redis-server",
            "--appendonly",
            "yes",
            "--save",
            "60",
            "1",
            "--requirepass",
            "${AP_REDIS_PASSWORD:?required}",
        ],
    },
    "baserow.yaml": {
        "service": "redis",
        "password": "BASEROW_REDIS_PASSWORD",
        "cli_auth": "REDISCLI_AUTH",
        "exec": "redis-server",
        "config": "/run/mte-baserow-redis/redis.conf",
        "tmpfs": (
            "/run/mte-baserow-redis:rw,noexec,nosuid,nodev,mode=0700,uid=999,gid=1000"
        ),
        "old_command": [
            "redis-server",
            "--appendonly",
            "yes",
            "--save",
            "60",
            "1",
            "--requirepass",
            "${BASEROW_REDIS_PASSWORD:?required}",
            "--databases",
            "16",
        ],
    },
    "searxng.yaml": {
        "service": "valkey",
        "password": "SEARXNG_VALKEY_PASSWORD",
        "cli_auth": "VALKEYCLI_AUTH",
        "exec": "valkey-server",
        "config": "/run/mte-searxng-valkey/valkey.conf",
        "tmpfs": (
            "/run/mte-searxng-valkey:rw,noexec,nosuid,nodev,mode=0700,uid=999,gid=1000"
        ),
        "old_command": [
            "valkey-server",
            "--save",
            "30",
            "1",
            "--loglevel",
            "warning",
            "--requirepass",
            "${SEARXNG_VALKEY_PASSWORD:?required}",
        ],
    },
}


def load_runtime(filename, spec):
    compose = yaml.safe_load(
        (SERVICES_DIR / Path(filename).stem / "compose.yaml").read_text()
    )
    return compose["services"][spec["service"]]


class ComposeRuntimeSecretCommandTests(unittest.TestCase):
    def test_no_compose_time_secret_placeholder_is_a_list_command_argument(self):
        offenders = []
        for path in sorted(SERVICES_DIR.glob("*/compose.yaml")):
            if path.parent.name == "firecrawl":
                continue
            compose = yaml.safe_load(path.read_text()) or {}
            for service_name, service in (compose.get("services") or {}).items():
                for field in ("entrypoint", "command"):
                    value = service.get(field)
                    if not isinstance(value, list):
                        continue
                    for index, argument in enumerate(value):
                        if not isinstance(argument, str):
                            continue
                        for match in COMPOSE_PLACEHOLDER.finditer(argument):
                            if SENSITIVE_NAME.search(match.group("name")):
                                offenders.append(
                                    f"{path.parent.name}:{service_name}:{field}[{index}]="
                                    f"{match.group(0)}"
                                )
        self.assertEqual(offenders, [])

    def test_redis_and_valkey_use_private_runtime_configs(self):
        for filename, spec in RUNTIMES.items():
            with self.subTest(filename=filename):
                runtime = load_runtime(filename, spec)
                command = runtime["command"]
                script = command[2]
                self.assertEqual(command[:2], ["/bin/sh", "-ec"])
                self.assertEqual(runtime["user"], "999:1000")
                self.assertEqual(runtime["tmpfs"], [spec["tmpfs"]])
                self.assertIn(f"printenv {spec['password']}", script)
                self.assertNotIn("${" + spec["password"], script)
                self.assertIn("umask 077", script)
                self.assertIn("chmod 0600", script)
                self.assertIn(f"unset password {spec['password']}", script)
                self.assertIn(spec["config"], script)
                self.assertIn(f'exec {spec["exec"]} "$$config"', script)

                health = " ".join(runtime["healthcheck"]["test"])
                self.assertIn(spec["cli_auth"] + "=", health)
                self.assertNotIn("-a ", health)
                if secret_file := spec.get("secret_file"):
                    self.assertIn(secret_file, script)
                    self.assertIn(f'chmod {spec["secret_mode"]} "$$secret"', script)
                    self.assertIn('$$(cat "$$secret")', script)
                    self.assertIn(secret_file, health)
                    self.assertIn("$$(cat", health)
                    self.assertNotIn(spec["password"], health)
                    self.assertEqual(runtime["security_opt"], spec["security_opt"])
                else:
                    self.assertIn(spec["password"], health)

    def test_final_manifests_encode_runtime_secret_hardening(self):
        for filename, spec in RUNTIMES.items():
            with self.subTest(filename=filename):
                runtime = load_runtime(filename, spec)
                rendered_command = " ".join(runtime["command"])
                self.assertNotIn("--requirepass ${", rendered_command)
                self.assertNotEqual(runtime["command"], spec["old_command"])
                self.assertIn("noexec", runtime["tmpfs"][0])
                self.assertIn("nosuid", runtime["tmpfs"][0])
                self.assertIn("nodev", runtime["tmpfs"][0])

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is required")
    def test_compose_render_never_materializes_password_in_command(self):
        password = "runtime-render-test-not-a-secret"
        for filename, spec in RUNTIMES.items():
            with self.subTest(filename=filename):
                runtime = load_runtime(filename, spec)
                minimal = {
                    "services": {
                        spec["service"]: {
                            "image": "alpine:3.23",
                            "user": runtime["user"],
                            "environment": runtime["environment"],
                            "command": runtime["command"],
                            "tmpfs": runtime["tmpfs"],
                            "healthcheck": runtime["healthcheck"],
                        }
                    }
                }
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    compose_path = root / "compose.yaml"
                    env_path = root / "platform.env"
                    compose_path.write_text(yaml.safe_dump(minimal, sort_keys=False))
                    env_path.write_text(f"{spec['password']}={password}\n")
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
                rendered = json.loads(result.stdout)["services"][spec["service"]]
                command = " ".join(rendered["command"])
                self.assertNotIn(password, command)
                self.assertNotIn("${" + spec["password"], command)
                self.assertIn(f"printenv {spec['password']}", command)
                health = " ".join(rendered["healthcheck"]["test"])
                self.assertNotIn(password, health)
                if secret_file := spec.get("secret_file"):
                    self.assertIn(secret_file, health)
                    self.assertIn("$$(cat", health)
                    self.assertNotIn("${" + spec["password"], health)
                else:
                    self.assertIn("${" + spec["password"] + ":?required}", health)


if __name__ == "__main__":
    unittest.main()
