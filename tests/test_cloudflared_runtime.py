from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/steps/cloudflare-tunnel.sh"
SERVER_CONFIG = ROOT / "tools/platform-cli/server-config.py"


class CloudflaredRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text()

    def runtime(
        self,
        values: dict[str, str],
        *,
        docker_values: dict[str, str] | None = None,
        system_values: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env_file = root / "platform.env"
            env_file.write_text(
                "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
            )
            runtime = root / "cloudflared-runtime.sh"
            runtime.write_text(
                self.source.replace(
                    "ENV_FILE='/root/.config/mte-secrets/platform.env'",
                    f"ENV_FILE={shlex.quote(str(env_file))}",
                )
            )
            runtime.chmod(0o755)

            fake_bin = root / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "args = sys.argv[1:]\n"
                "if args[0] == 'inspect':\n"
                "    template = args[args.index('--format') + 1]\n"
                "    if 'restartCount' in template:\n"
                '        print(\'{"name":"/mte-cloudflared","running":true,\'\n'
                '              \'"status":"running","restartCount":0,\'\n'
                '              \'"logDriver":"%s","logMaxSize":"%s",\'\n'
                '              \'"logMaxFiles":"%s"}\' % (\n'
                "                  os.environ['FAKE_LOG_DRIVER'],\n"
                "                  os.environ['FAKE_LOG_MAX_SIZE'],\n"
                "                  os.environ['FAKE_LOG_MAX_FILES'],\n"
                "              ))\n"
                "    elif '.Config.Image' in template:\n"
                "        print(os.environ['FAKE_IMAGE'])\n"
                "    elif '.HostConfig.RestartPolicy.Name' in template:\n"
                "        print(os.environ['FAKE_RESTART_POLICY'])\n"
                "    elif '.HostConfig.NetworkMode' in template:\n"
                "        print(os.environ['FAKE_NETWORK_MODE'])\n"
                "    elif '.Config.User' in template:\n"
                "        print(os.environ['FAKE_CONTAINER_USER'])\n"
                "    elif '.HostConfig.PidsLimit' in template:\n"
                "        print(os.environ['FAKE_PIDS_LIMIT'])\n"
                "    elif '.HostConfig.NanoCpus' in template:\n"
                "        print(os.environ['FAKE_NANO_CPUS'])\n"
                "    elif '.HostConfig.Memory' in template:\n"
                "        print(os.environ['FAKE_MEMORY_BYTES'])\n"
                "    elif 'json .Config.Cmd' in template:\n"
                "        print(os.environ['FAKE_COMMAND_JSON'])\n"
                "    elif '.HostConfig.LogConfig.Type' in template:\n"
                "        print(os.environ['FAKE_LOG_DRIVER'])\n"
                "    elif 'max-size' in template:\n"
                "        print(os.environ['FAKE_LOG_MAX_SIZE'])\n"
                "    elif 'max-file' in template:\n"
                "        print(os.environ['FAKE_LOG_MAX_FILES'])\n"
                "    else:\n"
                "        raise SystemExit(2)\n"
                "elif args[0] == 'logs':\n"
                "    pass\n"
                "else:\n"
                "    raise SystemExit(2)\n"
            )
            docker.chmod(0o755)
            stat_command = fake_bin / "stat"
            stat_command.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "if sys.argv[1:] and sys.argv[1] == '-c':\n"
                "    if sys.argv[2] == '%u:%g':\n"
                "        print(os.environ['FAKE_STAT_OWNER'])\n"
                "    elif sys.argv[2] == '%a':\n"
                "        print(os.environ['FAKE_STAT_MODE'])\n"
                "    else:\n"
                "        raise SystemExit(2)\n"
                "else:\n"
                "    raise SystemExit(2)\n"
            )
            stat_command.chmod(0o755)
            expected_docker_values = {
                "FAKE_IMAGE": values.get("CLOUDFLARED_IMAGE", "missing"),
                "FAKE_RESTART_POLICY": values.get(
                    "CLOUDFLARED_RESTART_POLICY", "missing"
                ),
                "FAKE_NETWORK_MODE": values.get("CLOUDFLARED_NETWORK_MODE", "missing"),
                "FAKE_CONTAINER_USER": values.get("CLOUDFLARED_USER", "missing"),
                "FAKE_PIDS_LIMIT": values.get("MTE_PIDS_SERVICE_LIMIT", "missing"),
                "FAKE_NANO_CPUS": "250000000",
                "FAKE_MEMORY_BYTES": "268435456",
                "FAKE_COMMAND_JSON": (
                    '["tunnel","--metrics","'
                    + values.get("CLOUDFLARED_METRICS_ADDRESS", "missing")
                    + '","--no-autoupdate","run","--token-file",'
                    '"/run/secrets/tunnel-token"]'
                ),
                "FAKE_LOG_DRIVER": "json-file",
                "FAKE_LOG_MAX_SIZE": values.get("MTE_DOCKER_LOG_MAX_SIZE", "missing"),
                "FAKE_LOG_MAX_FILES": values.get("MTE_DOCKER_LOG_MAX_FILES", "missing"),
                "FAKE_STAT_OWNER": "0:0",
                "FAKE_STAT_MODE": "600",
            }
            expected_docker_values.update(docker_values or {})
            expected_docker_values.update(system_values or {})
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                **expected_docker_values,
            }
            return subprocess.run(
                [str(runtime), "verify"],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

    @staticmethod
    def canonical_values() -> dict[str, str]:
        return {
            "CLOUDFLARED_IMAGE": "cloudflare/cloudflared:test",
            "CLOUDFLARED_CONTAINER_NAME": "mte-cloudflared",
            "CLOUDFLARED_RESTART_POLICY": "unless-stopped",
            "CLOUDFLARED_NETWORK_MODE": "host",
            "CLOUDFLARED_USER": "0:0",
            "CLOUDFLARED_CPU_LIMIT": "0.25",
            "CLOUDFLARED_MEMORY_LIMIT": "256m",
            "CLOUDFLARED_LOG_LOOKBACK": "5m",
            "CLOUDFLARED_METRICS_ADDRESS": "127.0.0.1:20241",
            "MTE_PIDS_SERVICE_LIMIT": "256",
            "MTE_DOCKER_LOG_MAX_SIZE": "10m",
            "MTE_DOCKER_LOG_MAX_FILES": "3",
        }

    def test_shell_syntax_is_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_server_config_seeds_all_cloudflared_runtime_controls(self) -> None:
        source = SERVER_CONFIG.read_text()
        expected = {
            "CLOUDFLARED_RESTART_POLICY": "unless-stopped",
            "CLOUDFLARED_NETWORK_MODE": "host",
            "CLOUDFLARED_USER": "0:0",
            "CLOUDFLARED_CPU_LIMIT": "0.25",
            "CLOUDFLARED_MEMORY_LIMIT": "256m",
            "CLOUDFLARED_LOG_LOOKBACK": "5m",
            "CLOUDFLARED_METRICS_ADDRESS": "127.0.0.1:20241",
            "MTE_PIDS_SERVICE_LIMIT": "256",
        }
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(source.count(f'"{key}": "{value}"'), 1)

    def test_install_uses_canonical_json_file_rotation(self) -> None:
        self.assertIn(
            "LOG_MAX_SIZE=$(require_canonical_value MTE_DOCKER_LOG_MAX_SIZE)",
            self.source,
        )
        self.assertIn(
            "LOG_MAX_FILES=$(require_canonical_value MTE_DOCKER_LOG_MAX_FILES)",
            self.source,
        )
        self.assertIn("--log-driver json-file", self.source)
        self.assertIn('--log-opt "max-size=${LOG_MAX_SIZE}"', self.source)
        self.assertIn('--log-opt "max-file=${LOG_MAX_FILES}"', self.source)
        unchanged = self.source.rsplit("cloudflared-runtime: unchanged", 1)[0]
        self.assertIn("&& runtime_config_matches", unchanged)
        self.assertIn("&& log_config_matches", self.source)
        install_tail = self.source.split("--token-file /run/secrets/tunnel-token", 1)[1]
        self.assertLess(
            install_tail.index("verify_runtime_config"),
            install_tail.index("cloudflared-runtime: installed"),
        )

    def test_install_uses_canonical_runtime_controls(self) -> None:
        assignments = {
            "RESTART_POLICY": "CLOUDFLARED_RESTART_POLICY",
            "NETWORK_MODE": "CLOUDFLARED_NETWORK_MODE",
            "CONTAINER_USER": "CLOUDFLARED_USER",
            "CPU_LIMIT": "CLOUDFLARED_CPU_LIMIT",
            "MEMORY_LIMIT": "CLOUDFLARED_MEMORY_LIMIT",
            "PIDS_LIMIT": "MTE_PIDS_SERVICE_LIMIT",
            "LOG_LOOKBACK": "CLOUDFLARED_LOG_LOOKBACK",
            "METRICS_ADDRESS": "CLOUDFLARED_METRICS_ADDRESS",
        }
        for variable, key in assignments.items():
            with self.subTest(key=key):
                self.assertIn(
                    f"{variable}=$(require_canonical_value {key})",
                    self.source,
                )

        for argument in (
            '--restart "$RESTART_POLICY"',
            '--network "$NETWORK_MODE"',
            '--user "$CONTAINER_USER"',
            '--pids-limit "$PIDS_LIMIT"',
            '--cpus "$CPU_LIMIT"',
            '--memory "$MEMORY_LIMIT"',
            'docker logs --since "$LOG_LOOKBACK"',
            'tunnel --metrics "$METRICS_ADDRESS" --no-autoupdate run',
        ):
            with self.subTest(argument=argument):
                self.assertIn(argument, self.source)

        for obsolete in (
            "--restart unless-stopped",
            "--network host",
            "--user 0:0",
            "--pids-limit 256",
            "--cpus 0.25",
            "--memory 256m",
            "docker logs --since 5m",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, self.source)

    def test_verify_accepts_exact_live_log_config(self) -> None:
        result = self.runtime(self.canonical_values())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cloudflared-runtime: running", result.stdout)

    def test_verify_rejects_live_log_config_drift(self) -> None:
        result = self.runtime(
            self.canonical_values(),
            docker_values={"FAKE_LOG_MAX_SIZE": "25m"},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("live container config does not match", result.stderr)

    def test_verify_rejects_each_live_runtime_control_drift(self) -> None:
        drift_cases = {
            "FAKE_IMAGE": "cloudflare/cloudflared:other",
            "FAKE_RESTART_POLICY": "always",
            "FAKE_NETWORK_MODE": "bridge",
            "FAKE_CONTAINER_USER": "65532:65532",
            "FAKE_PIDS_LIMIT": "128",
            "FAKE_NANO_CPUS": "500000000",
            "FAKE_MEMORY_BYTES": "536870912",
            "FAKE_COMMAND_JSON": (
                '["tunnel","--metrics","0.0.0.0:20241",'
                '"--no-autoupdate","run","--token-file",'
                '"/run/secrets/tunnel-token"]'
            ),
        }
        for key, value in drift_cases.items():
            with self.subTest(key=key):
                result = self.runtime(
                    self.canonical_values(),
                    docker_values={key: value},
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    "live container config does not match canonical config",
                    result.stderr,
                )

    def test_missing_or_invalid_canonical_rotation_fails_closed(self) -> None:
        missing = self.canonical_values()
        missing.pop("MTE_DOCKER_LOG_MAX_FILES")
        result = self.runtime(missing)
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing canonical MTE_DOCKER_LOG_MAX_FILES", result.stderr)

        invalid_size = self.canonical_values()
        invalid_size["MTE_DOCKER_LOG_MAX_SIZE"] = "unbounded"
        result = self.runtime(invalid_size)
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid MTE_DOCKER_LOG_MAX_SIZE", result.stderr)

        invalid_files = self.canonical_values()
        invalid_files["MTE_DOCKER_LOG_MAX_FILES"] = "0"
        result = self.runtime(invalid_files)
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid MTE_DOCKER_LOG_MAX_FILES", result.stderr)

    def test_canonical_config_must_be_root_owned_and_exactly_0600(self) -> None:
        result = self.runtime(
            self.canonical_values(),
            system_values={"FAKE_STAT_MODE": "644"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe canonical platform.env", result.stderr)

        result = self.runtime(
            self.canonical_values(),
            system_values={"FAKE_STAT_OWNER": "1000:1000"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe canonical platform.env", result.stderr)

    def test_missing_or_invalid_canonical_runtime_control_fails_closed(self) -> None:
        for key in (
            "CLOUDFLARED_RESTART_POLICY",
            "CLOUDFLARED_NETWORK_MODE",
            "CLOUDFLARED_USER",
            "CLOUDFLARED_CPU_LIMIT",
            "CLOUDFLARED_MEMORY_LIMIT",
            "CLOUDFLARED_LOG_LOOKBACK",
            "MTE_PIDS_SERVICE_LIMIT",
            "CLOUDFLARED_METRICS_ADDRESS",
        ):
            with self.subTest(missing=key):
                values = self.canonical_values()
                values.pop(key)
                result = self.runtime(values)
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"missing canonical {key}", result.stderr)

        invalid_values = {
            "CLOUDFLARED_RESTART_POLICY": "on-failure:unbounded",
            "CLOUDFLARED_NETWORK_MODE": "bridge",
            "CLOUDFLARED_USER": "root",
            "CLOUDFLARED_CPU_LIMIT": "0",
            "CLOUDFLARED_MEMORY_LIMIT": "unbounded",
            "CLOUDFLARED_LOG_LOOKBACK": "forever",
            "MTE_PIDS_SERVICE_LIMIT": "0",
            "CLOUDFLARED_METRICS_ADDRESS": "0.0.0.0:20241",
        }
        for key, value in invalid_values.items():
            with self.subTest(invalid=key):
                values = self.canonical_values()
                values[key] = value
                result = self.runtime(values)
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"invalid {key}", result.stderr)

    def test_token_install_path_requires_protected_secret_inputs(self) -> None:
        self.assertIn(
            "require_protected_path \"$SECRET_DIR\" directory 700 'Cloudflare secret directory'",
            self.source,
        )
        self.assertIn(
            "require_protected_path \"$TOKEN_FILE\" file 600 'tunnel token file'",
            self.source,
        )
        self.assertIn("! -L \"$path\"", self.source)


if __name__ == "__main__":
    unittest.main()
