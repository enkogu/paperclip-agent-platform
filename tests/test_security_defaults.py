from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class HostBootstrapConfigurationTests(unittest.TestCase):
    def test_resource_admission_defaults_are_canonical_non_secret_integers(self):
        renderer = load(
            "security_server_config_resource_preflight",
            "tools/platform-cli/server-config.py",
        )
        expected = {
            "MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB": "20971520",
            "MTE_RESOURCE_PREFLIGHT_MIN_MEM_AVAILABLE_KIB": "6291456",
            "MTE_RESOURCE_PREFLIGHT_MAX_SWAP_USED_KIB": "1048576",
            "MTE_RESOURCE_PREFLIGHT_MAX_LOAD_PER_CPU_MILLI": "1500",
            "MTE_RESOURCE_PREFLIGHT_MIN_ROOT_FREE_KIB": "31457280",
            "MTE_RESOURCE_PREFLIGHT_MIN_DOCKER_FREE_KIB": "31457280",
        }
        self.assertEqual(renderer.resource_preflight_values({}), expected)
        self.assertTrue(set(expected) <= renderer.OPTIONAL_OPERATOR_INPUT_KEYS)
        self.assertFalse(
            [key for key in expected if renderer.SENSITIVE_KEY_PATTERN.search(key)]
        )
        with self.assertRaisesRegex(
            renderer.ConfigError, "canonical unsigned integer"
        ):
            renderer.resource_preflight_values(
                {"MTE_RESOURCE_PREFLIGHT_MIN_MEM_TOTAL_KIB": "040"}
            )

    def test_host_bootstrap_does_not_install_dokploy_or_initialize_swarm(self):
        source = (ROOT / "deployment/steps/host.sh").read_text()
        self.assertNotIn("DOKPLOY_", source)
        self.assertNotIn("docker service", source)
        self.assertNotIn("docker swarm", source)

    def test_docker_artifact_and_port_contract_comes_from_canonical_env(self):
        source = (ROOT / "deployment/steps/host.sh").read_text()
        keys = (
            "MTE_DOCKER_APT_KEY_URL",
            "MTE_DOCKER_APT_REPOSITORY_URL",
            "MTE_DOCKER_APT_KEY_SHA256",
            "MTE_DOCKER_APT_KEY_FINGERPRINT",
            "MTE_DOCKER_CE_VERSION",
            "MTE_DOCKER_CLI_VERSION",
            "MTE_CONTAINERD_IO_VERSION",
            "MTE_DOCKER_COMPOSE_VERSION",
            "MTE_DOCKER_ALLOW_PROVIDER_MIGRATION",
            "MTE_DOCKER_UBUNTU_DOCKER_IO_VERSION",
            "MTE_DOCKER_UBUNTU_CONTAINERD_VERSION",
            "MTE_DOCKER_UBUNTU_COMPOSE_VERSION",
            "MTE_HOST_REQUIRED_TCP_PORTS",
        )
        for key in keys:
            self.assertIn(f"canonical_value {key}", source)
        self.assertNotIn("for port in 80 443 3000", source)
        self.assertNotIn("https://download.docker.com", source)

    def test_existing_ubuntu_provider_is_verified_without_daemon_migration(self):
        source = (ROOT / "deployment/steps/host.sh").read_text()
        ubuntu_branch = source.split(
            "if [[ -n $docker_io_installed ]]; then", maxsplit=1
        )[1].split("elif [[ -n $docker_ce_installed ]]; then", maxsplit=1)[0]
        self.assertIn(
            'require_package_version docker.io "$DOCKER_UBUNTU_DOCKER_IO_VERSION"',
            ubuntu_branch,
        )
        self.assertIn(
            'require_package_version containerd "$DOCKER_UBUNTU_CONTAINERD_VERSION"',
            ubuntu_branch,
        )
        self.assertNotIn("docker-ce", ubuntu_branch)
        self.assertNotIn("systemctl restart", source)
        self.assertIn(
            "MTE_DOCKER_ALLOW_PROVIDER_MIGRATION must remain false", source
        )

    def test_fresh_host_installs_and_verifies_exact_docker_ce_packages(self):
        source = (ROOT / "deployment/steps/host.sh").read_text()
        fresh_branch = source.split(
            "elif command -v docker >/dev/null 2>&1; then", maxsplit=1
        )[1].split("systemctl enable --now docker", maxsplit=1)[0]
        for package in (
            "docker-ce",
            "docker-ce-cli",
            "containerd.io",
            "docker-compose-plugin",
        ):
            self.assertIn(package, fresh_branch)
        self.assertIn("install_exact_packages", fresh_branch)
        self.assertIn("require_package_version", fresh_branch)
        self.assertIn("Docker APT key checksum mismatch", source)
        self.assertIn("Docker APT key fingerprint mismatch", source)

    def test_host_bootstrap_has_no_image_build_tooling(self):
        source = (ROOT / "deployment/steps/host.sh").read_text()
        config = (ROOT / "tools/platform-cli/server-config.py").read_text()
        platform = (ROOT / "tools/platform-cli/platform.py").read_text()
        lock = (ROOT / "config/dependencies.lock.json").read_text()
        for text in (source, config, platform, lock):
            self.assertNotIn("buildx", text.lower())


class HermesSecurityDefaultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = load("security_server_hermes", "tools/platform-cli/server-hermes.py")
        cls.renderer = load("security_server_config", "tools/platform-cli/server-config.py")

    def test_service_is_hardened_unless_admin_mode_is_explicit(self):
        safe = self.installer.render_service_unit(grant_platform_admin=False)
        privileged = self.installer.render_service_unit(grant_platform_admin=True)

        self.assertIn("NoNewPrivileges=true", safe)
        self.assertIn("ProtectSystem=strict", safe)
        self.assertIn("ReadWritePaths=/var/lib/mte-hermes", safe)
        self.assertNotIn("@@HERMES_PRIVILEGE_HARDENING@@", safe)
        self.assertNotIn("NoNewPrivileges=true", privileged)
        self.assertIn("Explicit host-admin mode", privileged)

        self.assertFalse(
            self.installer.parser().parse_args(["install"]).grant_platform_admin
        )
        self.assertTrue(
            self.installer.parser()
            .parse_args(["install", "--grant-platform-admin"])
            .grant_platform_admin
        )
        self.assertEqual(
            self.renderer.ONE_TIME_MIGRATION_SEEDS["HERMES_OPERATOR_MODE"],
            "unprivileged_service",
        )

    def test_default_policy_reconcile_removes_stale_unrestricted_sudo(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "mte-hermes"
            policy.write_text("mte-hermes ALL=(ALL) NOPASSWD: ALL\n")
            with mock.patch.object(self.installer, "SUDOERS_PATH", policy):
                self.installer.reconcile_admin_policy(False)
            self.assertFalse(policy.exists())

    def test_runtime_projection_excludes_unrelated_platform_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            runtime = root / "services/hermes.env"
            manifest = root / "projections-manifest.json"
            values = {
                key: f"unit-{index}"
                for index, key in enumerate(self.installer.REQUIRED_KEYS)
            }
            values.update(
                {
                    "MATTERMOST_URL": "http://127.0.0.1:18065",
                    "MATTERMOST_TOKEN": "unit-mattermost-token",
                    "MATTERMOST_ALLOWED_USERS": "a" * 26,
                    "UNRELATED_ROOT_SECRET": "must-not-be-projected",
                }
            )
            canonical.write_text(
                "".join(f"{key}={value}\n" for key, value in values.items())
            )
            source_sha = hashlib.sha256(canonical.read_bytes()).hexdigest()
            runtime.parent.mkdir(mode=0o700)
            runtime.write_text(
                self.renderer.service_projection_content(
                    "hermes",
                    set(self.renderer.HERMES_SERVICE_ENV_KEYS),
                    values,
                    source_sha,
                )
            )
            runtime.chmod(0o600)
            manifest.write_text(
                json.dumps(
                    {
                        "sourceSha256": source_sha,
                        "generatorVersion": self.renderer.GENERATOR_VERSION,
                        "projections": [
                            {
                                "path": str(runtime),
                                "contentSha256": hashlib.sha256(
                                    runtime.read_bytes()
                                ).hexdigest(),
                                "sourceSha256": source_sha,
                                "generatorVersion": self.renderer.GENERATOR_VERSION,
                            }
                        ],
                    }
                )
            )
            manifest.chmod(0o600)
            with (
                mock.patch.object(self.installer, "HERMES_RUNTIME_ENV_FILE", runtime),
                mock.patch.object(self.installer, "PROJECTIONS_MANIFEST", manifest),
            ):
                evidence = self.installer.runtime_credential_projection_evidence(
                    canonical, source_sha
                )
                self.assertTrue(
                    self.installer.runtime_credential_projection_matches(canonical)
                )

            projected = runtime.read_text()
            self.assertNotIn("UNRELATED_ROOT_SECRET", projected)
            self.assertNotIn("must-not-be-projected", projected)
            self.assertIn("PAPERCLIP_BRIDGE_API_KEY", projected)
            self.assertIn("PAPERCLIP_API_URL", projected)
            self.assertNotIn("HERMES_PAPERCLIP_API_KEY=", projected)
            self.assertIn("OPENAI_API_KEY=", projected)
            self.assertIn("OPENAI_BASE_URL=", projected)
            self.assertNotIn("HERMES_LLM_API_KEY=", projected)
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o600)
            self.assertTrue(evidence["manifestBound"])
            self.assertLess(evidence["keyCount"], len(values))
            self.assertEqual(
                self.renderer.HERMES_SERVICE_ENV_KEYS,
                self.installer.HERMES_RUNTIME_KEYS,
            )
            self.assertEqual(
                self.renderer.HERMES_NATIVE_ENV_NAMES,
                self.installer.HERMES_NATIVE_ENV_NAMES,
            )
            runtime.write_text(projected + "UNEXPECTED_KEY=drift\n")
            runtime.chmod(0o600)
            with (
                mock.patch.object(self.installer, "HERMES_RUNTIME_ENV_FILE", runtime),
                mock.patch.object(self.installer, "PROJECTIONS_MANIFEST", manifest),
            ):
                self.assertFalse(
                    self.installer.runtime_credential_projection_matches(canonical)
                )


class MattermostSecretTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bootstrap = load(
            "security_bootstrap_mattermost", "deployment/services/hermes/bootstrap-mattermost.py"
        )
        cls.provision = load("security_server_provision", "tools/platform-cli/server-provision.py")

    def test_bootstrap_password_is_sent_in_api_body(self):
        existing = mock.Mock(returncode=0, stdout="[]", stderr="")
        calls = []
        settings = self.bootstrap.BootstrapSettings(
            mattermost_url="http://127.0.0.1:18065",
            http_timeout_seconds=15,
            command_timeout_seconds=60,
            container_name_suffix="mattermost-1",
            bot_name="unit-hermes",
            operator_name="unit-operator",
            operator_email="operator@unit.invalid",
            team_name="unit-team",
            channel_name="unit-channel",
        )

        def api(_settings, path, **kwargs):
            calls.append((path, kwargs))
            if path == "/api/v4/users":
                return {"id": "operator-id", "username": "unit-operator"}, {}
            return {}, {}

        with (
            mock.patch.object(self.bootstrap, "mmctl", return_value=existing),
            mock.patch.object(self.bootstrap, "api_request", side_effect=api),
            mock.patch.object(
                self.bootstrap.secrets,
                "token_urlsafe",
                return_value="unit-password-never-in-argv",
            ),
        ):
            user, password = self.bootstrap.ensure_user(
                settings, "mattermost", "admin-token", None
            )
        self.assertEqual(user["id"], "operator-id")
        self.assertEqual(password, "unit-password-never-in-argv")
        create = next(row for row in calls if row[0] == "/api/v4/users")
        self.assertEqual(create[1]["body"]["password"], password)
        self.assertEqual(create[1]["bearer"], "admin-token")

    def test_provision_mattermost_source_has_no_password_cli_flag(self):
        for relative in (
            "deployment/services/hermes/bootstrap-mattermost.py",
            "tools/platform-cli/server-provision.py",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text()
                self.assertNotIn(
                    '"--password"',
                    source,
                    "Mattermost passwords must travel in JSON API bodies",
                )

    def test_provision_admin_creation_uses_json_request(self):
        source = (ROOT / "tools/platform-cli/server-provision.py").read_text()
        self.assertIn(
            'f"{ctx.url(component)}/api/v4/users"',
            source,
        )
        self.assertIn(
            '"password": saved["MATTERMOST_ADMIN_PASSWORD"]',
            source,
        )
        self.assertNotIn(
            "mmctl_password(",
            source,
        )


class PaperclipAuthenticationContractTests(unittest.TestCase):
    def test_runtime_supports_authenticated_public_without_secret_in_container_env(
        self,
    ):
        runtime_step = (ROOT / "deployment/steps/paperclip.sh").read_text()
        self.assertIn("PAPERCLIP_DEPLOYMENT_MODE", runtime_step)
        self.assertIn("PAPERCLIP_DEPLOYMENT_EXPOSURE", runtime_step)
        self.assertIn("authenticated public mode requires HTTPS", runtime_step)
        self.assertIn("/data/instances/default/.env:ro", runtime_step)
        self.assertIn("scripts/profile_catalog.py", runtime_step)
        self.assertIn('"$RUNTIME_ROOT/profiles"', runtime_step)
        self.assertIn("profile instructions ref missing", runtime_step)
        self.assertNotIn("-e PAPERCLIP_AGENT_JWT_SECRET=", runtime_step)
        self.assertNotIn('deploymentMode: "local_trusted"', runtime_step)
        self.assertIn('source: "configure"', runtime_step)
        self.assertNotIn('source: "mte-runtime-reconcile"', runtime_step)

    def test_kestra_route_is_private_reachable_and_has_no_public_listener(self):
        runtime_step = (ROOT / "deployment/steps/paperclip.sh").read_text()
        kestra_compose = (
            ROOT / "deployment/services/kestra/compose.yaml"
        ).read_text()
        daytona_step = (ROOT / "deployment/steps/daytona.sh").read_text()
        daytona_compose = (
            ROOT / "deployment/services/daytona/compose.yaml"
        ).read_text()
        canary = (ROOT / "workflows/kestra/platform-canary.yaml").read_text()
        e2e = (ROOT / "workflows/kestra/paperclip-github-e2e.yaml").read_text()

        for marker in (
            "PAPERCLIP_CONTROL_NETWORK='mte-control'",
            "PAPERCLIP_DAYTONA_API_SERVICE='mte-daytona-api'",
            "PAPERCLIP_DAYTONA_NETWORK=$(canonical_value MTE_DAYTONA_PAPERCLIP_NETWORK)",
            '--network-alias "$PAPERCLIP_CONTAINER_HOST"',
            'docker network connect "$PAPERCLIP_DAYTONA_NETWORK" mte-paperclip',
            '--publish "127.0.0.1:${PAPERCLIP_PORT}:${PAPERCLIP_PORT}"',
            'expected_binding = {f"{port}/tcp": [{"HostIp": "127.0.0.1"',
            '"publicListener": False',
            '"hostGatewayListener": False',
            '"extraProxyContainer": False',
            'if host.get("ExtraHosts"):',
            'if set(networks) != {control_network, daytona_network}:',
            '"daytonaDockerDnsRouteConfigured": True',
            '"daytonaNonApiServicesUnreachable": int(denied_target_count) == 7',
            '"daytonaApiNetworkMembershipExact": True',
            '"canonicalEnvironmentSha256": canonical_sha',
            '"producerPath": producer_path',
            '"producerSha256": producer_sha',
            "docker exec \"$kestra_container\" curl",
            'if (!response.ok) throw new Error(`unexpected HTTP ${response.status}`)',
            '[[ "$kestra_status" =~ ^2[0-9]{2}$ ]]',
            'bind: "lan"',
            'host: "0.0.0.0"',
            "PAPERCLIP_CONTAINER_HOST=$(canonical_value PAPERCLIP_CONTAINER_HOST)",
            "PAPERCLIP_DAYTONA_UPSTREAM_URL=$(canonical_value PAPERCLIP_DAYTONA_UPSTREAM_URL)",
            "PAPERCLIP_DAYTONA_UPSTREAM_URL host must be the reviewed Daytona API service",
            "PAPERCLIP_LEGACY_PORT=$(canonical_value PAPERCLIP_LEGACY_PORT)",
            "const url = process.argv[1];",
            "' \"${PAPERCLIP_DAYTONA_UPSTREAM_URL%/}/config\"",
            '("mte-daytona-db", 5432)',
            '("mte-daytona-redis", 6379)',
            '("mte-daytona-registry", 6000)',
            '("mte-daytona-minio", 9000)',
            '("mte-daytona-dex", 5556)',
            '("mte-daytona-runner", 3003)',
            '("mte-daytona-ssh-gateway", 2222)',
            "verify_runtime allow-daytona-pending",
            'run_paperclip_runtime(cfg, "verify")',
        ):
            source = (
                (ROOT / "tools/platform-cli/platform.py").read_text()
                if marker == 'run_paperclip_runtime(cfg, "verify")'
                else runtime_step
            )
            self.assertIn(marker, source)
        self.assertNotIn("PAPERCLIP_DAYTONA_PROXY", runtime_step)
        self.assertNotIn("proxy_checked", runtime_step)
        self.assertIn('-e PAPERCLIP_BIND=lan', runtime_step)
        self.assertIn('-e PAPERCLIP_ALLOWED_HOSTNAMES="$PAPERCLIP_CONTAINER_HOST"', runtime_step)
        self.assertIn(
            "SECRET_PAPERCLIP_BOARD_API_KEY: ${KESTRA_SECRET_PAPERCLIP_BOARD_API_KEY:-}",
            kestra_compose,
        )
        self.assertEqual(e2e.count("inputs.paperclip_base_url"), 17)
        self.assertEqual(e2e.count("secret('PAPERCLIP_BOARD_API_KEY')"), 17)
        self.assertNotIn("envs.PAPERCLIP_BOARD_API_KEY", e2e)
        self.assertNotIn("envs.paperclip_board_api_key", e2e)
        self.assertNotIn("PAPERCLIP_BOARD_API_KEY=", e2e)
        self.assertNotIn("PAPERCLIP_CONTAINER_HOST=${PAPERCLIP_CONTAINER_HOST:-", runtime_step)
        self.assertNotIn("DAYTONA_API_URL=${DAYTONA_API_URL:-", runtime_step)
        for forbidden in (
            "--network host",
            "--add-host",
            "start_daytona_host_proxy",
            "DAYTONA_LOOPBACK_PROXY_CPU_LIMIT",
            "DAYTONA_LOOPBACK_PROXY_MEMORY_LIMIT",
            "DAYTONA_LOOPBACK_PROXY_PIDS_LIMIT",
        ):
            self.assertNotIn(forbidden, runtime_step)
        self.assertNotIn("extra_hosts:", kestra_compose)
        self.assertIn("PAPERCLIP_BASE_URL:", kestra_compose)
        self.assertIn("{{ envs.PAPERCLIP_BASE_URL }}/api/health", canary)
        self.assertNotIn("host.docker.internal:3100", canary)
        self.assertEqual(daytona_compose.count("networks: [daytona, paperclip-api]"), 2)
        self.assertIn(
            "name: ${MTE_DAYTONA_PAPERCLIP_NETWORK:?required}",
            daytona_compose,
        )
        self.assertIn(
            'ensure_private_network "$paperclip_network"',
            daytona_step,
        )

    def test_private_route_defaults_are_canonical_and_secret_free(self):
        seeds = load(
            "security_server_config_paperclip",
            "tools/platform-cli/server-config.py",
        ).ONE_TIME_MIGRATION_SEEDS
        self.assertEqual(seeds["PAPERCLIP_CONTAINER_HOST"], "mte-paperclip")
        self.assertEqual(seeds["MTE_DAYTONA_NETWORK"], "mte-daytona-net")
        self.assertEqual(
            seeds["MTE_DAYTONA_PAPERCLIP_NETWORK"], "mte-daytona-api"
        )
        self.assertEqual(
            seeds["PAPERCLIP_DAYTONA_UPSTREAM_URL"],
            "http://mte-daytona-api:3000/api",
        )
        self.assertFalse(
            {
                "DAYTONA_LOOPBACK_PROXY_CPU_LIMIT",
                "DAYTONA_LOOPBACK_PROXY_MEMORY_LIMIT",
                "DAYTONA_LOOPBACK_PROXY_PIDS_LIMIT",
            }
            & set(seeds)
        )


if __name__ == "__main__":
    unittest.main()
