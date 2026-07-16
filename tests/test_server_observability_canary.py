import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-observability-canary.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "server_observability_canary",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ServerObservabilityCanaryTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_exact_hash_gate_is_fail_closed(self):
        good = "a" * 64
        config = {
            "_generated": {
                "sourceSha256": good,
                "generatorVersion": self.module.GENERATOR_VERSION,
            }
        }
        manifest = {
            "sourceSha256": good,
            "generatorVersion": self.module.GENERATOR_VERSION,
        }
        result = self.module.exact_hash_gate(good, config, manifest)
        self.assertEqual(result["sourceSha256"], good)
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.exact_hash_gate("b" * 64, config, manifest)
        self.assertEqual(raised.exception.code, "final_hash_not_stable")

    def test_runtime_values_load_hash_governed_service_projections(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            service_root = root / "services"
            service_root.mkdir()
            canonical = root / "platform.env"
            canonical.write_text("DATA_CONTENT_PROFILE=postgres-notion\nSHARED=same\n")
            components = (
                "postgres",
                *self.module.CORE_APPLICATION_COMPONENTS,
                "postgrest",
            )
            projections = []
            for component in (*components, "notion"):
                path = service_root / f"{component}.env"
                path.write_text(f"{component.upper()}_PROJECTED=ready\nSHARED=same\n")
                projections.append(
                    {
                        "path": str(path),
                        "contentSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "sourceSha256": hashlib.sha256(
                            canonical.read_bytes()
                        ).hexdigest(),
                        "generatorVersion": self.module.GENERATOR_VERSION,
                    }
                )
            dormant = service_root / "baserow.env"
            dormant.write_text("SHARED=drift\n")
            plane = root / "data-content-plane.json"
            plane.write_text(
                json.dumps(
                    {
                        "profile": "postgres-notion",
                        "componentIds": ["postgrest"],
                        "systemOfRecord": {"providerId": "postgres"},
                        "providers": {"notion": {"deployment": "external"}},
                    }
                )
            )
            projections.append(
                {
                    "path": str(plane),
                    "contentSha256": hashlib.sha256(plane.read_bytes()).hexdigest(),
                    "sourceSha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
                    "generatorVersion": self.module.GENERATOR_VERSION,
                }
            )
            config = {
                "spec": {"components": [{"id": component} for component in components]}
            }
            source_sha = hashlib.sha256(canonical.read_bytes()).hexdigest()
            manifest = {
                "sourceSha256": source_sha,
                "generatorVersion": self.module.GENERATOR_VERSION,
                "projections": projections,
            }
            with (
                mock.patch.object(self.module, "SERVICE_ENV_DIR", service_root),
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "DATA_CONTENT_PLANE", plane),
            ):
                values = self.module.runtime_values(
                    self.module.dotenv(canonical), config, manifest
                )
                self.assertEqual(values["ACTIVEPIECES_PROJECTED"], "ready")
                self.assertNotIn("BASEROW_PROJECTED", values)
                activepieces = service_root / "activepieces.env"
                activepieces.write_text("SHARED=drift\n")
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.runtime_values(
                        self.module.dotenv(canonical), config, manifest
                    )
        self.assertEqual(raised.exception.code, "service_projection_drift")

    def test_server_reconcilers_use_canonical_bin_directory(self):
        source = SCRIPT.read_text()
        self.assertEqual(self.module.SERVER_BIN, self.module.ROOT / "bin")
        self.assertNotIn('ROOT / "tools/platform-cli/server-', source)

    def test_correlated_payloads_share_run_trace_and_span(self):
        run_id, trace_id, span_id = "otel-123", "a" * 32, "b" * 16
        payloads = self.module.otlp_payloads(
            run_id,
            trace_id,
            span_id,
            123456789,
        )
        rendered = json.dumps(payloads)
        self.assertGreaterEqual(rendered.count(run_id), 6)
        self.assertGreaterEqual(rendered.count(trace_id), 4)
        self.assertIn('"traceId": "' + trace_id + '"', rendered)
        self.assertIn('"spanId": "' + span_id + '"', rendered)

    def test_v2_telemetry_evidence_contract_preserves_both_emitters(self):
        checks = self.module.telemetry_evidence_checks(
            emitters={
                "application": {"container": "app", "service": "app", "image": "a"},
                "runner": {"container": "runner", "service": "runner", "image": "r"},
            },
            app_statuses={"metrics": 202, "logs": 202, "traces": 202},
            runner_statuses={"metrics": 200, "logs": 200, "traces": 200},
            app_run_id="app-run",
            runner_run_id="runner-run",
            app_trace_id="a" * 32,
            runner_trace_id="b" * 32,
            runner_network={"temporaryAttachmentCleanupVerified": True},
            app_correlated={"metricSeries": 1, "logRecords": 2, "traceCount": 3},
            runner_correlated={"metricSeries": 4, "logRecords": 5, "traceCount": 6},
        )
        self.assertEqual(set(checks["C040"]["emitters"]), {"application", "runner"})
        self.assertEqual(checks["C044"]["traceCount"], 9)
        self.assertEqual(checks["C044"]["traceIds"], ["a" * 32, "b" * 32])
        self.assertEqual(self.module.OBSERVABILITY_EVIDENCE_SCHEMA_VERSION, 2)

    def test_c040_emits_otlp_from_running_paperclip_container(self):
        completed = mock.Mock(stdout="202\n", returncode=0)
        payload = {"resourceMetrics": [{"marker": "otel-safe"}]}
        with mock.patch.object(self.module, "run", return_value=completed) as runner:
            status = self.module.send_otlp_from_container(
                "mte-paperclip",
                "metrics",
                payload,
            )
        self.assertEqual(status, 202)
        argv = runner.call_args.args[0]
        self.assertEqual(
            argv[:4],
            [
                "docker",
                "exec",
                "-i",
                "mte-paperclip",
            ],
        )
        self.assertIn("http://127.0.0.1:4318/v1/metrics", argv)
        self.assertIn("otel-safe", runner.call_args.kwargs["stdin"])
        with self.assertRaises(self.module.CanaryError):
            self.module.send_otlp_from_container("host", "metrics", payload)

    def test_c040_emitter_is_an_exact_running_inventory_member(self):
        proof = self.module.require_otlp_emitters(
            [
                {"Name": "/mte-paperclip", "Image": "paperclip/native:exact"},
                {"Name": "/mte-daytona-runner", "Image": "daytona/runner:exact"},
            ]
        )
        self.assertEqual(proof["application"]["service"], "paperclip")
        self.assertEqual(proof["runner"]["service"], "daytona-runner")
        with self.assertRaises(self.module.CanaryError):
            self.module.require_otlp_emitters([])

    def test_c040_runner_origin_uses_exec_and_cleans_temporary_network(self):
        payloads = {"metrics": {"marker": "runner-safe"}}
        calls = []

        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["docker", "ps"]:
                return mock.Mock(stdout="otel-collector-1\n", returncode=0)
            if argv[:3] == ["docker", "inspect", "--format"]:
                return mock.Mock(
                    stdout=json.dumps(
                        {"mte-observability": {}}
                        if argv[-1] == "otel-collector-1"
                        else {"mte-daytona-net": {}}
                    )
                    + "\n",
                    returncode=0,
                )
            if argv[:3] == ["docker", "network", "connect"]:
                return mock.Mock(stdout="", stderr="", returncode=0)
            if argv[:3] == ["docker", "network", "disconnect"]:
                return mock.Mock(stdout="", stderr="", returncode=0)
            raise AssertionError(argv)

        with (
            mock.patch.object(self.module, "run", side_effect=command),
            mock.patch.object(
                self.module,
                "send_otlp_from_runner",
                return_value=202,
            ) as sender,
        ):
            statuses, lifecycle = self.module.runner_otlp_bundle(
                "mte-daytona-runner",
                payloads,
            )
        self.assertEqual(statuses, {"metrics": 202})
        self.assertTrue(lifecycle["temporaryAttachmentCleanupVerified"])
        sender.assert_called_once()
        self.assertIn(
            [
                "docker",
                "network",
                "disconnect",
                "mte-observability",
                "mte-daytona-runner",
            ],
            calls,
        )

    def test_probe_metric_matches_existing_vmalert_labels(self):
        rendered = json.dumps(
            self.module.probe_metric_payload("otel-safe", 0),
        )
        for value in (
            "probe_success",
            "platform_health",
            "observability-canary",
            "mte-canary:otel-safe",
        ):
            self.assertIn(value, rendered)
        self.assertIn('"asInt": "0"', rendered)

    def test_alert_failure_always_emits_resolving_one(self):
        with (
            mock.patch.object(self.module, "send_otlp") as send,
            mock.patch.object(
                self.module,
                "wait_for",
                side_effect=self.module.CanaryError("canary_timeout", "timeout"),
            ),
        ):
            with self.assertRaises(self.module.CanaryError):
                self.module.fire_and_resolve_alert("otel-safe", "mattermost-db")
        values = [
            call.args[1]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0][
                "gauge"
            ]["dataPoints"][0]["asInt"]
            for call in send.call_args_list
        ]
        self.assertEqual(values, ["0", "1"])

    def test_container_discovery_uses_stable_volume_identity(self):
        required = {
            **self.module.POSTGRES_VOLUMES,
            "activepieces-redis": self.module.REDIS_VOLUME,
        }
        items = [
            {"Name": f"/{key}-random", "Mounts": [{"Type": "volume", "Name": volume}]}
            for key, volume in required.items()
        ]
        found = self.module.require_containers(items)
        self.assertEqual(found["mattermost"], "mattermost-random")
        self.assertEqual(
            found["activepieces-redis"],
            "activepieces-redis-random",
        )

    def test_application_paths_use_health_ports_and_compose_siblings(self):
        ports = {
            "mattermost": 18065,
            "activepieces": 18090,
            "firecrawl": 13002,
            "kestra": 18081,
            "searxng": 18088,
            "postgrest": 18087,
        }
        config = {
            "spec": {
                "components": [
                    {"id": "postgres"},
                    *[
                        {
                            "id": key,
                            "health": {"url": f"http://127.0.0.1:{port}/health"},
                        }
                        for key, port in ports.items()
                    ],
                ]
            }
        }

        def item(name, project, service, port=None):
            bindings = {"8080/tcp": [{"HostPort": str(port)}]} if port else {}
            return {
                "Name": name,
                "Ports": bindings,
                "Labels": {
                    "com.docker.compose.project": project,
                    "com.docker.compose.service": service,
                },
            }

        items = [
            item("mm", "mm-project", "mattermost", 18065),
            item("ap", "ap-project", "app", 18090),
            item("ap-worker", "ap-project", "worker"),
            item("fire", "fire-project", "api", 13002),
            item("kestra", "kestra-project", "kestra", 18081),
            item("search", "search-project", "searxng", 18088),
            item("postgrest", "postgrest-project", "postgrest", 18087),
        ]
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            plane = Path(temporary) / "data-content-plane.json"
            plane.write_text(
                json.dumps(
                    {
                        "profile": "postgres-notion",
                        "componentIds": ["postgrest"],
                        "systemOfRecord": {"providerId": "postgres"},
                        "providers": {"notion": {"deployment": "external"}},
                    }
                )
            )
            with mock.patch.object(self.module, "DATA_CONTENT_PLANE", plane):
                paths = self.module.application_paths(
                    config, items, {"DATA_CONTENT_PROFILE": "postgres-notion"}
                )
                dormant = {
                    "spec": {
                        "components": [
                            *config["spec"]["components"],
                            {"id": "baserow"},
                        ]
                    }
                }
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.application_paths(
                        dormant,
                        items,
                        {"DATA_CONTENT_PROFILE": "postgres-notion"},
                    )
        self.assertEqual(paths["postgrest"], "postgrest")
        self.assertEqual(paths["activepieces-worker"], "ap-worker")
        self.assertEqual(len(paths), 7)
        self.assertEqual(raised.exception.code, "runtime_profile_invalid")

    def test_runtime_profile_accepts_only_exact_reviewed_component_sets(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            plane_path = Path(temporary) / "data-content-plane.json"
            with mock.patch.object(self.module, "DATA_CONTENT_PLANE", plane_path):
                for profile, contract in self.module.PROFILE_RUNTIME_CONTRACTS.items():
                    providers = {
                        provider: {"deployment": "external"}
                        for provider in contract["externalProviders"]
                    }
                    plane_path.write_text(
                        json.dumps(
                            {
                                "profile": profile,
                                "componentIds": list(contract["componentIds"]),
                                "systemOfRecord": {"providerId": "postgres"},
                                "providers": providers,
                            }
                        )
                    )
                    components = {
                        "postgres",
                        *self.module.CORE_APPLICATION_COMPONENTS,
                        *contract["componentIds"],
                    }
                    config = {
                        "spec": {
                            "components": [
                                {"id": component} for component in sorted(components)
                            ]
                        }
                    }
                    resolved = self.module.runtime_profile(
                        config, {"DATA_CONTENT_PROFILE": profile}
                    )
                    self.assertEqual(resolved["profile"], profile)

                config["spec"]["components"].append({"id": "unknown-provider"})
                plane_path.write_text(
                    json.dumps(
                        {
                            "profile": profile,
                            "componentIds": [
                                *contract["componentIds"],
                                "unknown-provider",
                            ],
                            "systemOfRecord": {"providerId": "postgres"},
                            "providers": providers,
                        }
                    )
                )
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.runtime_profile(
                        config,
                        {"DATA_CONTENT_PROFILE": profile},
                    )
        self.assertEqual(raised.exception.code, "runtime_profile_invalid")

    def test_blackbox_requires_all_targets_successful_and_fresh(self):
        now = self.module.time.time()
        targets = {
            "9router": "http://127.0.0.1:20128/api/health",
            "kestra": "http://127.0.0.1:18081/health",
            "paperclip": "http://127.0.0.1:18110/api/health",
            "toolhive": "http://127.0.0.1:18880/api/openapi.json",
            "activepieces": "http://127.0.0.1:18090/api/v1/health",
            "baserow": "http://127.0.0.1:18085/api/_health/",
            "wikijs": "http://127.0.0.1:18086/healthz",
            "mattermost": "http://127.0.0.1:18065/api/v4/system/ping",
            "firecrawl": "http://127.0.0.1:13002/",
            "searxng": "http://127.0.0.1:18088/",
            "observability": "http://127.0.0.1:13000/api/health",
        }
        config = {
            "spec": {
                "components": [
                    {"id": component, "required": True, "health": {"url": url}}
                    for component, url in targets.items()
                ]
            }
        }
        rows = [
            {"metric": {"service": service, "server.address": url}, "value": [now, "1"]}
            for service, url in targets.items()
        ]
        with mock.patch.object(
            self.module,
            "prom_query",
            return_value=rows,
        ) as query:
            proof = self.module.blackbox_proof(config)
            self.assertTrue(proof["allSuccessful"])
            self.assertEqual(len(proof["declaredTargets"]), 11)
        self.assertEqual(
            query.call_args.args[0],
            'probe_success{service.name="platform_health"}',
        )
        rows.pop()
        with mock.patch.object(self.module, "prom_query", return_value=rows):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.blackbox_proof(config)
        self.assertEqual(raised.exception.code, "blackbox_targets_failed")

    def test_postgres_proves_insert_read_delete_without_secret_argv(self):
        apps = {
            role: role + "-container"
            for role in (
                "postgrest",
                "mattermost",
                "activepieces-app",
                "activepieces-worker",
                "firecrawl-api",
                "kestra",
                "searxng",
            )
        }
        values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "MTE_POSTGRES_POSTGRES_IMAGE": "postgres:test",
            "POSTGREST_DB_HOST": "mte-postgres",
            "POSTGREST_DB_PORT": "5432",
            "POSTGREST_DB_LOGIN_ROLE": "authenticator",
            "POSTGREST_DATA_DB_NAME": "agent_data",
            "POSTGREST_AUTHENTICATOR_PASSWORD": "hidden-postgrest",
            "MATTERMOST_DB_USER": "mm",
            "MATTERMOST_DB_NAME": "mattermost",
            "MATTERMOST_DB_PASSWORD": "hidden-mm",
            "MTE_ACTIVEPIECES_APP_ENV_AP_POSTGRES_HOST": "mte-ap-postgres",
            "MTE_ACTIVEPIECES_APP_ENV_AP_POSTGRES_PORT": "5432",
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_POSTGRES_HOST": "mte-ap-postgres",
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_POSTGRES_PORT": "5432",
            "AP_POSTGRES_USERNAME": "ap",
            "AP_POSTGRES_DATABASE": "ap",
            "AP_POSTGRES_PASSWORD": "hidden-ap",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_HOST": "nuq-postgres",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_PORT": "5432",
            "FIRECRAWL_DB_USER": "nuq",
            "FIRECRAWL_DB_NAME": "nuq",
            "FIRECRAWL_DB_PASSWORD": "hidden-firecrawl",
            "KESTRA_DB_PASSWORD": "hidden-kestra",
        }
        completed = mock.Mock(stdout="1\n1\n0\n", returncode=0)
        with mock.patch.object(
            self.module,
            "run",
            return_value=completed,
        ) as runner:
            proof = self.module.postgres_rw_delete(values, apps, "otel-safe")
        by_role = {row["role"]: row for row in proof}
        self.assertEqual(by_role["kestra"]["remaining"], 0)
        self.assertEqual(set(by_role), set(apps) - {"searxng"})
        self.assertEqual(runner.call_count, 6)
        for call in runner.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[:3], ["docker", "run", "--rm"])
            self.assertNotIn("hidden-", " ".join(argv))
            self.assertIn("PGPASSWORD", call.kwargs["env"])
            self.assertIn("DELETE FROM", call.kwargs["stdin"])
            self.assertIn("RETURNING 1", call.kwargs["stdin"])

    def test_redis_requires_noauth_then_authenticated_pong(self):
        unauth = mock.Mock(
            stdout="NOAUTH Authentication required.\n",
            stderr="",
            returncode=0,
        )
        authenticated = mock.Mock(
            stdout="PONG\n",
            stderr="",
            returncode=0,
        )
        apps = {
            role: role + "-container"
            for role in (
                "mattermost",
                "activepieces-app",
                "activepieces-worker",
                "firecrawl-api",
                "kestra",
                "searxng",
                "postgrest",
            )
        }
        values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "MTE_ACTIVEPIECES_DATA_REDIS_IMAGE": "redis:test",
            "AP_REDIS_URL": "redis://:hidden-ap@mte-ap-redis:6379/0",
            "FIRECRAWL_REDIS_URL": "redis://:hidden-fire@redis:6379/0",
            "SEARXNG_VALKEY_URL": "redis://:hidden-search@valkey:6379/0",
        }
        with mock.patch.object(
            self.module, "run", side_effect=[unauth, authenticated] * 4
        ) as runner:
            proof = self.module.redis_authenticated_paths(values, apps)
        self.assertEqual(
            {row["role"] for row in proof},
            {"activepieces-app", "activepieces-worker", "firecrawl-api", "searxng"},
        )
        self.assertTrue(all(row["unauthenticatedRejected"] for row in proof))
        self.assertTrue(all(row["authenticatedPing"] == "PONG" for row in proof))
        for index, call in enumerate(runner.call_args_list):
            self.assertNotIn("hidden-", " ".join(call.args[0]))
            if index % 2:
                self.assertIn("MTE_CANARY_REDIS_URL", call.kwargs["env"])
        values["FIRECRAWL_REDIS_URL"] = "redis://redis:6379/0"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.redis_path_specs(values, apps)
        self.assertEqual(raised.exception.code, "redis_path_auth_missing")

    def test_datastore_path_cardinality_follows_each_supported_profile(self):
        base_values = {
            "POSTGREST_DB_HOST": "mte-postgres",
            "POSTGREST_DB_PORT": "5432",
            "POSTGREST_DB_LOGIN_ROLE": "authenticator",
            "POSTGREST_DATA_DB_NAME": "agent_data",
            "POSTGREST_AUTHENTICATOR_PASSWORD": "hidden-postgrest",
            "MATTERMOST_DB_USER": "mm",
            "MATTERMOST_DB_NAME": "mattermost",
            "MATTERMOST_DB_PASSWORD": "hidden-mm",
            "MTE_ACTIVEPIECES_APP_ENV_AP_POSTGRES_HOST": "mte-ap-postgres",
            "MTE_ACTIVEPIECES_APP_ENV_AP_POSTGRES_PORT": "5432",
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_POSTGRES_HOST": "mte-ap-postgres",
            "MTE_ACTIVEPIECES_WORKER_ENV_AP_POSTGRES_PORT": "5432",
            "AP_POSTGRES_USERNAME": "ap",
            "AP_POSTGRES_DATABASE": "ap",
            "AP_POSTGRES_PASSWORD": "hidden-ap",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_HOST": "nuq-postgres",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_PORT": "5432",
            "FIRECRAWL_DB_USER": "nuq",
            "FIRECRAWL_DB_NAME": "nuq",
            "FIRECRAWL_DB_PASSWORD": "hidden-firecrawl",
            "KESTRA_DB_PASSWORD": "hidden-kestra",
            "AP_REDIS_URL": "redis://:hidden-ap@redis:6379/0",
            "FIRECRAWL_REDIS_URL": "redis://:hidden-fire@redis:6379/0",
            "SEARXNG_VALKEY_URL": "redis://:hidden-search@valkey:6379/0",
            "BASEROW_DB_HOST": "mte-postgres",
            "BASEROW_DB_PORT": "5432",
            "BASEROW_DB_USER": "baserow",
            "BASEROW_DB_NAME": "baserow",
            "BASEROW_DB_PASSWORD": "hidden-baserow",
            "BASEROW_REDIS_PASSWORD": "hidden-baserow",
            "BASEROW_REDIS_HOST": "redis",
            "BASEROW_REDIS_PORT": "6379",
            "BASEROW_REDIS_DB": "8",
            "WIKIJS_DB_HOST": "mte-postgres",
            "WIKIJS_DB_PORT": "5432",
            "WIKIJS_DB_USER": "wikijs",
            "WIKIJS_DB_NAME": "wikijs",
            "WIKIJS_DB_PASSWORD": "hidden-wikijs",
            "NOCODB_DB_HOST": "mte-postgres",
            "NOCODB_DB_PORT": "5432",
            "NOCODB_META_DB_USER": "nocodb",
            "NOCODB_META_DB_NAME": "nocodb",
            "NOCODB_META_DB_PASSWORD": "hidden-nocodb",
        }
        expected = {
            "postgres-notion": (6, 4),
            "baserow-wikijs": (8, 5),
            "postgres-postgrest-nocodb-nocodocs": (7, 4),
        }
        common_apps = {
            role: role + "-container"
            for role in (
                "mattermost",
                "activepieces-app",
                "activepieces-worker",
                "firecrawl-api",
                "kestra",
                "searxng",
            )
        }
        for profile, (postgres_count, redis_count) in expected.items():
            values = {**base_values, "DATA_CONTENT_PROFILE": profile}
            apps = {
                **common_apps,
                **{
                    component: component + "-container"
                    for component in self.module.PROFILE_RUNTIME_CONTRACTS[profile][
                        "componentIds"
                    ]
                },
            }
            self.assertEqual(
                len(self.module.postgres_path_specs(values, apps)), postgres_count
            )
            self.assertEqual(
                len(self.module.redis_path_specs(values, apps)), redis_count
            )

        invalid = {**base_values, "DATA_CONTENT_PROFILE": "unknown-provider"}
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.postgres_path_specs(invalid, common_apps)
        self.assertEqual(
            raised.exception.code,
            "unsupported_data_content_profile",
        )

    def test_alert_runtime_config_requires_receiver_and_otel_label(self):
        webhook = "https://mattermost.invalid/hooks/not-a-real-secret"
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            (root / "alertmanager.yml").write_text(
                "route:\n  receiver: mattermost\nreceivers:\n"
                "  - name: mattermost\n    slack_configs:\n"
                f"      - api_url: {webhook}\n        send_resolved: true\n"
            )
            (root / "rules.yml").write_text(
                'expr: probe_success{service.name="platform_health"} == 0\n'
            )
            proof = self.module.runtime_alert_config(
                {"MATTERMOST_ALERT_WEBHOOK_URL": webhook},
                root,
            )
            self.assertTrue(proof["mattermostReceiverReady"])
            self.assertTrue(proof["webhookFingerprintMatch"])
            self.assertEqual(
                proof["canonicalWebhookFingerprintSha256"],
                proof["deployedWebhookFingerprintSha256"],
            )
            self.assertNotIn(webhook, json.dumps(proof))
            (root / "rules.yml").write_text(
                'expr: probe_success{job="platform_health"} == 0\n'
            )
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.runtime_alert_config(
                    {"MATTERMOST_ALERT_WEBHOOK_URL": webhook},
                    root,
                )
        self.assertEqual(raised.exception.code, "vmalert_selector_not_deployed")

    def test_c048_records_author_channel_and_deletes_exact_canary_posts(self):
        state = mock.Mock(
            stdout="2|t|t|mte-admin|mte-alerts|1|1\n",
            returncode=0,
        )
        cleanup = mock.Mock(stdout="2\n0\n", returncode=0)
        with mock.patch.object(
            self.module,
            "run",
            side_effect=[state, cleanup],
        ) as runner:
            post = self.module.mattermost_post_state("mattermost-db", "otel-safe")
            deleted = self.module.mattermost_cleanup_posts(
                "mattermost-db",
                "otel-safe",
            )
        self.assertEqual(post["author"], "mte-admin")
        self.assertEqual(post["channel"], "mte-alerts")
        self.assertTrue(post["resolved"])
        self.assertEqual(
            deleted,
            {
                "deletedPosts": 2,
                "remainingPosts": 0,
                "cleanupVerified": True,
            },
        )
        self.assertIn("DELETE FROM", runner.call_args_list[1].kwargs["stdin"])
        self.assertIn("otel-safe", runner.call_args_list[1].kwargs["stdin"])

    def test_c061_and_c062_require_dedicated_api_and_engine_binding(self):
        resources = [
            {
                "component": "baserow",
                "composeId": "compose-1",
                "status": "done",
                "appName": "mte-baserow",
                "composeType": "docker-compose",
                "sourceType": "raw",
            }
        ]
        with mock.patch.object(
            self.module,
            "run_json_command",
            return_value={
                "apiKeyAuthenticated": True,
                "credentialRef": "DOKPLOY_API_TOKEN",
                "credentialSource": "/root/.config/mte-secrets/platform.env",
                "credentialFingerprintSha256": "a" * 64,
                "projectCount": 1,
                "resources": resources,
            },
        ):
            control = self.module.dokploy_control_plane_proof(["baserow"])
        self.assertTrue(control["apiKeyAuthenticated"])

        def command(argv, **_kwargs):
            if argv[:2] == ["docker", "version"]:
                return mock.Mock(
                    stdout=json.dumps({"Version": "27.0", "ApiVersion": "1.47"}),
                    returncode=0,
                )
            if argv[:2] == ["docker", "ps"]:
                return mock.Mock(stdout="baserow-1\n", returncode=0)
            if argv[:2] == ["docker", "inspect"]:
                labels = {
                    "com.docker.compose.project": "mte-baserow",
                    "com.docker.compose.service": "baserow",
                    "com.docker.compose.config-hash": "b" * 64,
                }
                return mock.Mock(
                    stdout=(
                        json.dumps("/baserow-1")
                        + "\t"
                        + json.dumps("running")
                        + "\t"
                        + json.dumps(labels)
                        + "\n"
                    ),
                    returncode=0,
                )
            raise AssertionError(argv)

        with mock.patch.object(self.module, "run", side_effect=command):
            engine = self.module.docker_engine_proof(resources)
        self.assertTrue(engine["allContainersRunning"])
        self.assertEqual(engine["projects"][0]["services"], ["baserow"])

    def test_c070_requires_root_only_secret_store_and_legacy_lock_modes(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary) / "secrets"
            root.mkdir(mode=0o700)
            integrations = root / "integrations"
            integrations.mkdir(mode=0o700)
            canonical = root / "platform.env"
            manifest_path = root / "projections-manifest.json"
            lock = root / ".platform-env.lock"
            legacy = root / "platform.env.lock"
            integration = integrations / "mattermost.env"
            for path in (canonical, manifest_path, lock, legacy, integration):
                path.write_text("test-only\n")
                path.chmod(0o600)
            manifest = {"projections": [{"path": str(integration)}]}
            original_stat = Path.stat

            def root_owned_stat(path, *args, **kwargs):
                value = original_stat(path, *args, **kwargs)
                fields = list(value)
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            with (
                mock.patch.object(self.module, "SECRET_ROOT", root),
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "MANIFEST", manifest_path),
                mock.patch.object(Path, "stat", root_owned_stat),
            ):
                proof = self.module.secret_permissions_proof(manifest)
                self.assertEqual(proof["fileMode"], "0600")
                legacy.chmod(0o644)
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.secret_permissions_proof(manifest)
        self.assertEqual(raised.exception.code, "secret_permissions_invalid")

    def test_observability_template_queries_actual_otel_service_name_label(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        command = compose["services"]["config-init"]["command"][0]
        dashboard_source = command.split(
            "cat > /config/dashboards-json/platform.json <<'EOF'\n",
            1,
        )[1].split("\nEOF\n", 1)[0]
        dashboard = json.loads(dashboard_source)
        dashboard_queries = [
            target["expr"]
            for panel in dashboard["panels"]
            for target in panel.get("targets", [])
            if "expr" in target
        ]
        dashboard_queries.extend(
            variable["query"]["query"]
            for variable in dashboard["templating"]["list"]
            if isinstance(variable.get("query"), dict)
        )
        self.assertEqual(
            sum(
                'service.name="platform_health"' in query for query in dashboard_queries
            ),
            3,
        )
        self.assertIn(
            'expr: probe_success{service.name="platform_health"} == 0',
            command,
        )
        self.assertNotIn('job="platform_health"', command)

    def test_blackbox_scrape_has_exact_required_component_health_targets(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        command = compose["services"]["config-init"]["command"][0]
        otel = command.split("cat > /config/otel.yml <<'EOF'\n", 1)[1].split(
            "\nEOF\n",
            1,
        )[0]
        scrape = yaml.safe_load(otel)["receivers"]["prometheus"]["config"][
            "scrape_configs"
        ]
        blackbox = next(row for row in scrape if row["job_name"] == "platform_health")
        targets = {row["targets"][0] for row in blackbox["static_configs"]}
        self.assertEqual(
            targets,
            {
                "http://127.0.0.1:20128/api/health",
                "http://127.0.0.1:18081/health",
                "http://127.0.0.1:3100/api/health",
                "http://127.0.0.1:18880/api/openapi.json",
                "http://127.0.0.1:18090/api/v1/health",
                "http://127.0.0.1:18085/api/_health/",
                "http://127.0.0.1:18086/healthz",
                "http://127.0.0.1:18065/api/v4/system/ping",
                "http://127.0.0.1:13002/",
                "http://127.0.0.1:18088/",
                "http://127.0.0.1:13000/api/health",
            },
        )

    def test_grafana_double_reconcile_creates_only_once(self):
        state = {
            "datasources": {
                uid: {"id": index + 1, "uid": uid, **expected}
                for index, (uid, expected) in enumerate(self.module.DATASOURCES.items())
            },
            "folder": {
                "id": 10,
                "uid": "mte-platform",
                "title": "MTE Platform",
            },
            "accounts": [],
            "creates": 0,
        }

        def call(method, path, auth, body=None, allow_status=None):
            if path.startswith("/api/datasources/uid/"):
                return 200, state["datasources"][path.rsplit("/", 1)[-1]]
            if path == "/api/folders/mte-platform":
                return 200, state["folder"]
            if path.startswith("/api/serviceaccounts/search"):
                return 200, {"serviceAccounts": list(state["accounts"])}
            if method == "POST" and path == "/api/serviceaccounts":
                state["creates"] += 1
                state["accounts"].append(
                    {
                        "id": 20,
                        "name": body["name"],
                        "role": body["role"],
                    }
                )
                return 201, state["accounts"][0]
            raise AssertionError((method, path))

        with mock.patch.object(
            self.module,
            "grafana_call",
            side_effect=call,
        ):
            result = self.module.grafana_reconcile_twice(
                {
                    "Authorization": "Basic hidden",
                }
            )
        self.assertTrue(result["idempotent"])
        self.assertEqual(state["creates"], 1)
        self.assertEqual(
            result["first"]["sha256"],
            result["second"]["sha256"],
        )

    def test_grafana_reconcile_reuses_provisioned_folder_by_title(self):
        calls = []
        account = {"id": 20, "name": "mte-observability-prober"}

        def call(method, path, auth, body=None, allow_status=None):
            calls.append((method, path))
            if path.startswith("/api/datasources/uid/"):
                uid = path.rsplit("/", 1)[-1]
                expected = self.module.DATASOURCES[uid]
                return 200, {"id": 1, "uid": uid, **expected}
            if path == "/api/folders/mte-platform":
                return 404, None
            if path == "/api/folders?limit=1000":
                return 200, [
                    {"id": 10, "uid": "generated-uid", "title": "MTE Platform"}
                ]
            if path.startswith("/api/serviceaccounts/search"):
                return 200, {"serviceAccounts": [account]}
            raise AssertionError((method, path))

        with mock.patch.object(
            self.module,
            "grafana_call",
            side_effect=call,
        ):
            result = self.module.reconcile_grafana_once({})
        self.assertEqual(result["folderUid"], "generated-uid")
        self.assertNotIn(("POST", "/api/folders"), calls)

    def test_indexed_stable_projection_removes_volatile_and_secret_values(self):
        projected = self.module.stable_projection(
            {
                "id": "stable-id",
                "status": "running",
                "updatedAt": "tomorrow",
                "password": "must-not-survive",
                "credentialFingerprint": "sha256:stable",
                "nested": [{"uid": "one", "action": "deployed"}],
            }
        )
        self.assertEqual(
            projected,
            {
                "credentialFingerprint": "sha256:stable",
                "id": "stable-id",
                "nested": [{"uid": "one"}],
            },
        )

    def test_indexed_inventory_rejects_duplicate_resource_identity(self):
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.assert_no_list_duplicates(
                [
                    {"id": "same", "name": "first"},
                    {"id": "same", "name": "second"},
                ]
            )
        self.assertEqual(
            raised.exception.code,
            "indexed_inventory_duplicate",
        )

    def test_postgres_notion_indexed_reconcile_uses_only_active_providers(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            secret_root = root / "secrets"
            bin_root = root / "bin"
            evidence_root = root / "evidence"
            for path in (secret_root, bin_root, evidence_root):
                path.mkdir()
            canonical = secret_root / "platform.env"
            canonical.write_text(
                "DATA_CONTENT_PROFILE=postgres-notion\n"
                "NOTION_TOKEN=secret-unit-notion-token\n"
                "POSTGREST_ACTIVEPIECES_TOKEN=secret-unit-postgrest-token\n"
            )
            canonical.chmod(0o600)
            canonical_sha = hashlib.sha256(canonical.read_bytes()).hexdigest()
            producer_hashes = {}
            for name in (
                "server-postgrest.py",
                "server-notion.py",
                "server-activepieces-provision-verify.py",
            ):
                path = bin_root / name
                path.write_text(f"# {name}\n")
                producer_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            plane = root / "data-content-plane.json"
            plane.write_text(
                json.dumps(
                    {
                        "profile": "postgres-notion",
                        "componentIds": ["postgrest"],
                        "systemOfRecord": {"providerId": "postgres"},
                        "providers": {
                            "postgres": {"deployment": "core"},
                            "postgrest": {"deployment": "profile-component"},
                            "notion": {"deployment": "external"},
                        },
                        "binding": {"sourceSha256": canonical_sha},
                        "_generated": {"sourceSha256": canonical_sha},
                    }
                )
            )
            config = {
                "spec": {
                    "components": [
                        {"id": "postgrest", "compose": "postgrest.compose.yaml"},
                        {
                            "id": "activepieces",
                            "compose": "activepieces.compose.yaml",
                        },
                    ]
                }
            }
            values = self.module.dotenv(canonical)
            postgrest_result = {
                "ok": True,
                "status": "converged",
                "canonical": {"changedKeys": []},
                "roleBindings": {"distinct": True},
            }
            notion_result = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "NotionConnectorProvision",
                "status": "converged",
                "ok": True,
                "dataContentProfile": "postgres-notion",
                "changedKeys": [],
                "created": {
                    "documentsPage": False,
                    "database": False,
                    "dataSource": False,
                },
                "schema": {"exact": True, "changed": False},
                "redacted": True,
            }
            activepieces_result = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "ActivepiecesProvisionEvidence",
                "dataContentProfile": "postgres-notion",
                "status": "passed",
                "ok": True,
                "canonicalSourceSha256": canonical_sha,
                "producerSha256": producer_hashes[
                    "server-activepieces-provision-verify.py"
                ],
                "managedFlows": [
                    {"id": str(index), "status": "ready"} for index in range(3)
                ],
                "credentialSlots": [
                    {
                        "id": "variable-id",
                        "type": "project-variable",
                        "status": "ready",
                        "valueRedacted": True,
                    }
                ],
                "mcpTokenIssuable": True,
                "mcpTokenPersisted": False,
                "secondRunNoOp": True,
                "mutationCount": 0,
                "duplicateCount": 0,
            }
            evidence_specs = (
                (
                    evidence_root / "postgrest.json",
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "PostgrestVerification",
                        "status": "passed",
                        "ok": True,
                        "profile": "postgres-notion",
                        "canonicalSourceSha256": canonical_sha,
                        "producerSha256": producer_hashes["server-postgrest.py"],
                    },
                ),
                (
                    evidence_root / "notion.json",
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "NotionConnectorVerification",
                        "status": "passed",
                        "ok": True,
                        "dataContentProfile": "postgres-notion",
                        "canonicalSourceSha256": canonical_sha,
                        "producerSha256": producer_hashes["server-notion.py"],
                    },
                ),
                (evidence_root / "activepieces.json", activepieces_result),
            )
            for path, document in evidence_specs:
                path.write_text(json.dumps(document))
                path.chmod(0o600)
            calls = []

            def command(argv, **_kwargs):
                name = Path(argv[1]).name
                calls.append(name)
                return {
                    "server-postgrest.py": postgrest_result,
                    "server-notion.py": notion_result,
                    "server-activepieces-provision-verify.py": activepieces_result,
                }[name]

            with (
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "DATA_CONTENT_PLANE", plane),
                mock.patch.object(self.module, "SERVER_BIN", bin_root),
                mock.patch.object(
                    self.module,
                    "POSTGREST_VERIFY_EVIDENCE",
                    evidence_specs[0][0],
                ),
                mock.patch.object(
                    self.module,
                    "NOTION_VERIFY_EVIDENCE",
                    evidence_specs[1][0],
                ),
                mock.patch.object(
                    self.module,
                    "ACTIVEPIECES_PROVISION_EVIDENCE",
                    evidence_specs[2][0],
                ),
                mock.patch.object(self.module, "run_json_command", side_effect=command),
            ):
                result = self.module.profile_declarative_reconcile(config, values)
                dormant = {
                    **config,
                    "spec": {
                        "components": [
                            *config["spec"]["components"],
                            {
                                "id": "baserow",
                                "compose": "baserow.compose.yaml",
                            },
                        ]
                    },
                }
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.postgres_notion_contract(dormant, values)
            self.assertEqual(
                calls,
                [
                    "server-postgrest.py",
                    "server-notion.py",
                    "server-activepieces-provision-verify.py",
                ],
            )
            self.assertEqual(result["summary"]["providerComponents"], ["postgrest"])
            self.assertEqual(result["summary"]["externalProviders"], ["notion"])
            self.assertNotIn("secret-unit", json.dumps(result))
            self.assertRegex(result["identitySha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                raised.exception.code,
                "indexed_data_content_profile_invalid",
            )

    def test_indexed_finalize_requires_stable_second_noop_pass(self):
        source_hash = "a" * 64
        gate = {
            "sourceSha256": source_hash,
            "generatorVersion": self.module.GENERATOR_VERSION,
        }
        identity = {"dokployIds": {"paperclip": "compose-1"}}
        producers = self.module.producer_hashes()
        host_producers = self.module.installed_producer_hashes(
            self.module.HOST_DOKPLOY_PRODUCERS
        )
        host_evidence = {
            "status": "passed",
            "sourceGate": gate,
            "producerHashes": {
                "server-host-dokploy-acceptance.py": host_producers[
                    "server-host-dokploy-acceptance.py"
                ],
                "server-dokploy.py": host_producers["server-dokploy.py"],
            },
            "C061": {
                "status": "pass",
                "apiKeyAuthenticated": True,
                "operations": [
                    "list",
                    "create",
                    "update",
                    "status",
                    "update",
                    "status",
                    "delete",
                ],
                "resourceCreated": True,
                "resourceUpdated": True,
                "statusObserved": True,
                "resourceDeleted": True,
            },
            "C062": {
                "status": "pass",
                "configHashChanged": True,
                "firstRevision": {
                    "containerStates": ["running"],
                    "configHashes": ["one"],
                },
                "secondRevision": {
                    "containerStates": ["running"],
                    "configHashes": ["two"],
                },
                "engineResourcesCreated": {
                    "containers": 1,
                    "volumes": 1,
                    "networks": 1,
                },
                "cleanup": {
                    "noResidualResources": True,
                    "remaining": {"containers": 0, "volumes": 0, "networks": 0},
                },
            },
        }
        control_checks = {
            "C061": {"status": "pass", "apiKeyAuthenticated": True},
            "C062": {"status": "pass", "allContainersRunning": True},
        }
        first = {
            "sourceGate": gate,
            "producerHashes": producers,
            "before": {"identity": identity, "identitySha256": "before"},
            "after": {"identity": identity, "identitySha256": "stable"},
            "dokployActions": {"paperclip": "deployed"},
            "C061": control_checks["C061"],
            "C062": control_checks["C062"],
            "provisionerIdentitySha256": "provisioner-stable",
            "toolhiveIdentitySha256": "toolhive-stable",
            "dataContentProfile": "postgres-notion",
            "dataContentIdentitySha256": "data-content-stable",
            "dataContentDeclarativeEvidence": {"profile": "postgres-notion"},
        }
        second = {
            "sourceGate": gate,
            "producerHashes": producers,
            "before": {"identity": identity, "identitySha256": "stable"},
            "after": {"identity": identity, "identitySha256": "stable"},
            "dokployActions": {"paperclip": "unchanged"},
            "C061": control_checks["C061"],
            "C062": control_checks["C062"],
            "provisionerIdentitySha256": "provisioner-stable",
            "toolhiveIdentitySha256": "toolhive-stable",
            "dataContentProfile": "postgres-notion",
            "dataContentIdentitySha256": "data-content-stable",
            "dataContentDeclarativeEvidence": {"profile": "postgres-notion"},
        }
        config = {"_generated": gate}
        manifest = gate.copy()
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            pass_one, pass_two = root / "pass-one.json", root / "pass-two.json"
            final, host = root / "final.json", root / "host.json"
            host.write_text(json.dumps(host_evidence))
            host_sha = hashlib.sha256(host.read_bytes()).hexdigest()
            first["hostDokployEvidenceSha256"] = host_sha
            second["hostDokployEvidenceSha256"] = host_sha
            pass_one.write_text(json.dumps(first))
            pass_two.write_text(json.dumps(second))
            with (
                mock.patch.object(self.module, "CONFIG", root / "config.json"),
                mock.patch.object(self.module, "MANIFEST", root / "manifest.json"),
                mock.patch.object(
                    self.module,
                    "INDEX_PASS",
                    {1: pass_one, 2: pass_two},
                ),
                mock.patch.object(self.module, "INDEX_FINAL", final),
                mock.patch.object(self.module, "HOST_DOKPLOY_EVIDENCE", host),
                mock.patch.object(
                    self.module,
                    "load_json",
                    side_effect=lambda path: config
                    if path == root / "config.json"
                    else manifest
                    if path == root / "manifest.json"
                    else json.loads(path.read_text()),
                ),
            ):
                result = self.module.finalize_indexed_idempotency(source_hash)
                self.assertTrue(result["secondPassNoChange"])
                self.assertEqual(result["dataContentProfile"], "postgres-notion")
                self.assertEqual(
                    result["profileCoverage"],
                    [
                        "postgres-ssot-postgrest-provisioning",
                        "notion-external-connector-provisioning",
                        "activepieces-declarative-resources",
                    ],
                )
                self.assertEqual(
                    result["producerSha256"],
                    hashlib.sha256(Path(self.module.__file__).read_bytes()).hexdigest(),
                )
                self.assertEqual(final.stat().st_mode & 0o777, 0o600)
                second["dokployActions"]["paperclip"] = "deployed"
                pass_two.write_text(json.dumps(second))
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.finalize_indexed_idempotency(source_hash)
        self.assertEqual(raised.exception.code, "indexed_second_pass_changed")

    def test_secret_scan_rejects_exact_and_connection_values(self):
        with self.assertRaises(self.module.CanaryError) as exact:
            self.module.scan_for_secrets(
                {"value": "secret-value"},
                {"TOKEN": "secret-value"},
            )
        self.assertEqual(exact.exception.code, "evidence_secret_leak")
        with self.assertRaises(self.module.CanaryError) as shaped:
            self.module.scan_for_secrets(
                {"value": "redis://user:pass@example.invalid"},
                {},
            )
        self.assertEqual(shaped.exception.code, "evidence_secret_pattern")

    def test_atomic_evidence_is_mode_0600(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            path = Path(temporary) / "evidence" / "canary.json"
            self.module.atomic_json(path, {"status": "passed"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(path.read_text())["status"],
                "passed",
            )


if __name__ == "__main__":
    unittest.main()
