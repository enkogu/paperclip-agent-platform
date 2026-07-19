import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
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

    def runtime_values(self, **overrides):
        values = {
            "OBSERVABILITY_OTLP_HTTP_URL": "http://127.0.0.1:4318",
            "OBSERVABILITY_CONTAINER_OTLP_HTTP_URL": "http://otel-collector:4318",
            "MTE_OBSERVABILITY_VICTORIAMETRICS_PORT_1_MAPPING": "127.0.0.1:18428:8428",
            "MTE_OBSERVABILITY_VICTORIALOGS_PORT_1_MAPPING": "127.0.0.1:19428:9428",
            "MTE_OBSERVABILITY_VICTORIATRACES_PORT_1_MAPPING": "127.0.0.1:10428:10428",
            "MTE_OBSERVABILITY_VMALERT_PORT_1_MAPPING": "127.0.0.1:18881:8880",
            "MTE_OBSERVABILITY_ALERTMANAGER_PORT_1_MAPPING": "127.0.0.1:19093:9093",
            "OBSERVABILITY_HEALTH_URL": "http://127.0.0.1:13000/api/health",
            "OBSERVABILITY_QUERY_TIMEOUT_SECONDS": "90",
            "OBSERVABILITY_POLL_INTERVAL_SECONDS": "5",
            "OBSERVABILITY_SERIES_MAX_AGE_SECONDS": "180",
            "OBSERVABILITY_ALERT_FIRE_TIMEOUT_SECONDS": "300",
            "OBSERVABILITY_ALERT_RESOLVE_TIMEOUT_SECONDS": "420",
            "OBSERVABILITY_ALERT_POLL_INTERVAL_SECONDS": "20",
            "OBSERVABILITY_HTTP_TIMEOUT_SECONDS": "30",
            "OBSERVABILITY_COMMAND_TIMEOUT_SECONDS": "60",
        }
        values.update(overrides)
        return values

    def runtime(self, **overrides):
        return self.module.observability_runtime(self.runtime_values(**overrides))

    def test_observability_runtime_is_fail_closed_and_propagates_mutations(self):
        runtime = self.runtime(
            MTE_OBSERVABILITY_VICTORIAMETRICS_PORT_1_MAPPING="127.0.0.9:28428:18428",
            OBSERVABILITY_CONTAINER_OTLP_HTTP_URL="http://collector.changed:14318",
            OBSERVABILITY_QUERY_TIMEOUT_SECONDS="123",
        )
        self.assertEqual(runtime.victoriametrics_url, "http://127.0.0.9:28428")
        self.assertEqual(
            runtime.datasources["victoriametrics"]["url"],
            "http://victoriametrics:18428",
        )
        self.assertEqual(runtime.container_otlp_url, "http://collector.changed:14318")
        self.assertEqual(runtime.query_timeout_seconds, 123)

        for key, value in (
            ("OBSERVABILITY_QUERY_TIMEOUT_SECONDS", "0"),
            ("OBSERVABILITY_OTLP_HTTP_URL", "https://user:pass@example.test:4318"),
            ("MTE_OBSERVABILITY_VMALERT_PORT_1_MAPPING", "not-a-mapping"),
        ):
            with self.subTest(key=key):
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.observability_runtime(
                        self.runtime_values(**{key: value})
                    )
                self.assertEqual(raised.exception.code, "invalid_observability_runtime")

        missing = self.runtime_values()
        del missing["OBSERVABILITY_ALERT_RESOLVE_TIMEOUT_SECONDS"]
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.observability_runtime(missing)
        self.assertEqual(raised.exception.code, "missing_observability_runtime")

    def test_endpoint_and_timeout_mutations_reach_network_calls(self):
        runtime = self.runtime(
            MTE_OBSERVABILITY_VICTORIAMETRICS_PORT_1_MAPPING="127.0.0.7:28429:8429",
            OBSERVABILITY_HEALTH_URL="http://127.0.0.8:23000/api/health",
            OBSERVABILITY_HTTP_TIMEOUT_SECONDS="47",
        )
        with mock.patch.object(
            self.module,
            "request_json",
            side_effect=[
                (200, {"status": "success", "data": {"result": []}}),
                (200, {"database": "ok"}),
            ],
        ) as request:
            self.module.prom_query("up", runtime)
            self.module.grafana_call("GET", "/api/health", {}, runtime)
        self.assertTrue(
            request.call_args_list[0].args[1].startswith("http://127.0.0.7:28429/")
        )
        self.assertEqual(request.call_args_list[0].kwargs["timeout"], 47)
        self.assertEqual(
            request.call_args_list[1].args[1],
            "http://127.0.0.8:23000/api/health",
        )
        self.assertEqual(request.call_args_list[1].kwargs["timeout"], 47)

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
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
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
                self.assertEqual(values["MATTERMOST_PROJECTED"], "ready")
                mattermost = service_root / "mattermost.env"
                mattermost.write_text("SHARED=drift\n")
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

    def test_correlated_query_counts_single_victorialogs_json_record(self):
        runtime = self.runtime()
        run_id = "otel-app-single"
        trace_id = "a" * 32
        with (
            mock.patch.object(
                self.module,
                "prom_query",
                return_value=[{"metric": {"run_id": run_id}}],
            ),
            mock.patch.object(
                self.module,
                "request_json",
                side_effect=[
                    (200, {"run_id": run_id, "trace_id": trace_id}),
                    (200, {"data": [{"traceID": trace_id}]}),
                ],
            ),
        ):
            proof = self.module.query_correlated_data(run_id, trace_id, runtime)

        self.assertEqual(proof["metricSeries"], 1)
        self.assertEqual(proof["logRecords"], 1)
        self.assertEqual(proof["traceCount"], 1)

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
            app_network={"temporaryAttachmentCleanupVerified": True},
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
                self.runtime(),
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
        self.assertIn("http://otel-collector:4318/v1/metrics", argv)
        self.assertIn("otel-safe", runner.call_args.kwargs["stdin"])
        with self.assertRaises(self.module.CanaryError):
            self.module.send_otlp_from_container(
                "host", "metrics", payload, self.runtime()
            )

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
                self.runtime(),
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

    def test_c040_application_origin_also_uses_temporary_network(self):
        payloads = {"metrics": {"marker": "application-safe"}}
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
                        else {"mte-control": {}}
                    )
                    + "\n",
                    returncode=0,
                )
            if argv[:3] in (
                ["docker", "network", "connect"],
                ["docker", "network", "disconnect"],
            ):
                return mock.Mock(stdout="", stderr="", returncode=0)
            raise AssertionError(argv)

        with (
            mock.patch.object(self.module, "run", side_effect=command),
            mock.patch.object(
                self.module,
                "send_otlp_from_container",
                return_value=202,
            ) as sender,
        ):
            statuses, lifecycle = self.module.container_otlp_bundle(
                "mte-paperclip", payloads, self.runtime()
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
                "mte-paperclip",
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
            mock.patch.object(self.module, "mattermost_cleanup_posts"),
            mock.patch.object(
                self.module,
                "wait_for",
                side_effect=self.module.CanaryError("canary_timeout", "timeout"),
            ),
        ):
            with self.assertRaises(self.module.CanaryError):
                self.module.fire_and_resolve_alert(
                    "otel-safe", "mattermost-db", self.runtime()
                )
        values = [
            call.args[1]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0][
                "gauge"
            ]["dataPoints"][0]["asInt"]
            for call in send.call_args_list
        ]
        self.assertEqual(values, ["0", "1"])

    def test_container_discovery_uses_stable_volume_identity(self):
        required = dict(self.module.POSTGRES_VOLUMES)
        items = [
            {"Name": f"/{key}-random", "Mounts": [{"Type": "volume", "Name": volume}]}
            for key, volume in required.items()
        ]
        found = self.module.require_containers(items)
        self.assertEqual(found["mattermost"], "mattermost-random")

    def test_application_paths_use_health_ports_and_compose_siblings(self):
        ports = {
            "mattermost": 18065,
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
            item("fire", "fire-project", "api", 13002),
            item("kestra", "kestra-project", "kestra", 18081),
            item("search", "search-project", "searxng", 18088),
            item("postgrest", "postgrest-project", "postgrest", 18087),
        ]
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
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
        self.assertEqual(paths["postgrest"], "postgrest")
        self.assertEqual(len(paths), 5)

    def test_runtime_profile_accepts_only_exact_reviewed_component_sets(self):
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
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
            proof = self.module.blackbox_proof(config, self.runtime())
            self.assertTrue(proof["allSuccessful"])
            self.assertEqual(len(proof["declaredTargets"]), 8)
        self.assertEqual(
            query.call_args.args[0],
            'probe_success{service.name="platform_health"}',
        )
        rows.pop()
        with mock.patch.object(self.module, "prom_query", return_value=rows):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.blackbox_proof(config, self.runtime())
        self.assertEqual(raised.exception.code, "blackbox_targets_failed")

    def test_postgres_proves_insert_read_delete_without_secret_argv(self):
        apps = {
            role: role + "-container"
            for role in (
                "postgrest",
                "mattermost",
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
            "MATTERMOST_DB_HOST": "mte-mattermost-postgres",
            "MATTERMOST_DB_PORT": "5432",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_HOST": "nuq-postgres",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_PORT": "5432",
            "FIRECRAWL_DB_USER": "nuq",
            "FIRECRAWL_DB_NAME": "nuq",
            "FIRECRAWL_DB_PASSWORD": "hidden-firecrawl",
            "KESTRA_DB_PASSWORD": "hidden-kestra",
            "KESTRA_DB_HOST": "mte-kestra-postgres",
            "KESTRA_DB_PORT": "5432",
            "KESTRA_DB_USER": "kestra",
            "KESTRA_DB_NAME": "kestra",
        }
        completed = mock.Mock(stdout="1\n1\n0\n", returncode=0)
        with mock.patch.object(
            self.module,
            "run",
            return_value=completed,
        ) as runner:
            proof = self.module.postgres_rw_delete(
                values, apps, "otel-safe", self.runtime()
            )
        by_role = {row["role"]: row for row in proof}
        self.assertEqual(by_role["kestra"]["remaining"], 0)
        self.assertEqual(set(by_role), set(apps) - {"searxng"})
        self.assertEqual(runner.call_count, 4)
        for call in runner.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[:4], ["docker", "run", "-i", "--rm"])
            self.assertIn("-i", argv)
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
                "firecrawl-api",
                "kestra",
                "searxng",
                "postgrest",
            )
        }
        values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "MTE_SEARXNG_VALKEY_IMAGE": "valkey:test",
            "FIRECRAWL_REDIS_URL": "redis://:hidden%3Afire@redis:6379/0",
            "SEARXNG_VALKEY_URL": "redis://:hidden%3Asearch@valkey:6379/0",
        }
        with mock.patch.object(
            self.module, "run", side_effect=[unauth, authenticated] * 2
        ) as runner:
            proof = self.module.redis_authenticated_paths(values, apps, self.runtime())
        self.assertEqual(
            {row["role"] for row in proof},
            {"firecrawl-api", "searxng"},
        )
        self.assertTrue(all(row["unauthenticatedRejected"] for row in proof))
        self.assertTrue(all(row["authenticatedPing"] == "PONG" for row in proof))
        for index, call in enumerate(runner.call_args_list):
            self.assertNotIn("hidden-", " ".join(call.args[0]))
            if index % 2:
                self.assertIn("REDISCLI_AUTH", call.kwargs["env"])
                self.assertNotIn("-u", call.args[0])
                self.assertFalse(
                    any(argument.startswith("redis://") for argument in call.args[0])
                )
        values["FIRECRAWL_REDIS_URL"] = "redis://redis:6379/0"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.redis_path_specs(values, apps)
        self.assertEqual(raised.exception.code, "redis_path_auth_missing")

    def test_datastore_path_cardinality_matches_active_profile(self):
        values = {
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "POSTGREST_DB_HOST": "mte-postgres",
            "POSTGREST_DB_PORT": "5432",
            "POSTGREST_DB_LOGIN_ROLE": "authenticator",
            "POSTGREST_DATA_DB_NAME": "agent_data",
            "POSTGREST_AUTHENTICATOR_PASSWORD": "hidden-postgrest",
            "MATTERMOST_DB_USER": "mm",
            "MATTERMOST_DB_NAME": "mattermost",
            "MATTERMOST_DB_PASSWORD": "hidden-mm",
            "MATTERMOST_DB_HOST": "mte-mattermost-postgres",
            "MATTERMOST_DB_PORT": "5432",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_HOST": "nuq-postgres",
            "MTE_FIRECRAWL_API_ENV_POSTGRES_PORT": "5432",
            "FIRECRAWL_DB_USER": "nuq",
            "FIRECRAWL_DB_NAME": "nuq",
            "FIRECRAWL_DB_PASSWORD": "hidden-firecrawl",
            "KESTRA_DB_PASSWORD": "hidden-kestra",
            "KESTRA_DB_HOST": "mte-kestra-postgres",
            "KESTRA_DB_PORT": "5432",
            "KESTRA_DB_USER": "kestra",
            "KESTRA_DB_NAME": "kestra",
            "FIRECRAWL_REDIS_URL": "redis://:hidden-fire@redis:6379/0",
            "SEARXNG_VALKEY_URL": "redis://:hidden-search@valkey:6379/0",
        }
        apps = {
            role: role + "-container"
            for role in (
                "postgrest",
                "mattermost",
                "firecrawl-api",
                "kestra",
                "searxng",
            )
        }
        self.assertEqual(len(self.module.postgres_path_specs(values, apps)), 4)
        self.assertEqual(len(self.module.redis_path_specs(values, apps)), 2)

        values["DATA_CONTENT_PROFILE"] = "unknown-provider"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.postgres_path_specs(values, apps)
        self.assertEqual(raised.exception.code, "unsupported_data_content_profile")

    def test_alert_runtime_config_requires_receiver_and_otel_label(self):
        webhook = "http://127.0.0.1:18065/hooks/not-a-real-secret"
        deployed_webhook = "http://mattermost:8065/hooks/not-a-real-secret"
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
            root = Path(temporary)
            (root / "alertmanager.yml").write_text(
                "route:\n  receiver: mattermost\nreceivers:\n"
                "  - name: mattermost\n    slack_configs:\n"
                f"      - api_url: {deployed_webhook}\n        send_resolved: true\n"
            )
            (root / "rules.yml").write_text(
                'expr: probe_success{service.name="platform_health"} == 0\n'
            )
            with self.assertRaises(self.module.CanaryError) as missing:
                self.module.runtime_alert_config(
                    {"MATTERMOST_ALERT_WEBHOOK_URL": ""},
                    self.runtime(),
                    root,
                )
            self.assertEqual(missing.exception.code, "mattermost_receiver_not_deployed")
            proof = self.module.runtime_alert_config(
                {"MATTERMOST_ALERT_WEBHOOK_URL": webhook},
                self.runtime(),
                root,
            )
            self.assertTrue(proof["mattermostReceiverReady"])
            self.assertTrue(proof["webhookPathPreserved"])
            self.assertNotEqual(
                proof["canonicalWebhookFingerprintSha256"],
                proof["deployedWebhookFingerprintSha256"],
            )
            self.assertNotIn(webhook, json.dumps(proof))
            self.assertNotIn(deployed_webhook, json.dumps(proof))
            (root / "rules.yml").write_text(
                'expr: probe_success{job="platform_health"} == 0\n'
            )
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.runtime_alert_config(
                    {"MATTERMOST_ALERT_WEBHOOK_URL": webhook},
                    self.runtime(),
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
            post = self.module.mattermost_post_state(
                "mattermost-db", "otel-safe", self.runtime()
            )
            deleted = self.module.mattermost_cleanup_posts(
                "mattermost-db",
                "otel-safe",
                self.runtime(),
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
        state_sql = runner.call_args_list[0].kwargs["stdin"]
        cleanup_sql = runner.call_args_list[1].kwargs["stdin"]
        self.assertEqual(
            state_sql,
            "SELECT count(*),"
            "coalesce(bool_or(lower(p.message || ' ' || p.props::text) "
            "LIKE '%firing%'),false),"
            "coalesce(bool_or(lower(p.message || ' ' || p.props::text) "
            "LIKE '%resolved%'),false),"
            "coalesce(min(nullif(u.username,'')),"
            "min(nullif(p.props::jsonb->>'override_username','')),'incoming-webhook'),"
            "coalesce(min(c.name),''),"
            "count(distinct p.userid),count(distinct p.channelid) "
            "FROM public.posts p "
            "LEFT JOIN public.users u ON u.id=p.userid "
            "LEFT JOIN public.channels c ON c.id=p.channelid "
            "WHERE lower(p.message || ' ' || p.props::text) "
            "LIKE '%otel-safe%';",
        )
        self.assertNotIn("lower(message", state_sql)
        self.assertNotIn(" || props::text", state_sql)
        self.assertIn("DELETE FROM public.posts", cleanup_sql)
        self.assertIn("SELECT count(*) FROM public.posts", cleanup_sql)
        self.assertIn("otel-safe", cleanup_sql)
        for legacy_identifier in ('"Posts"', '"Users"', '"Channels"'):
            with self.subTest(identifier=legacy_identifier):
                self.assertNotIn(legacy_identifier, state_sql)
                self.assertNotIn(legacy_identifier, cleanup_sql)

    def test_c048_fails_closed_when_mattermost_schema_query_fails(self):
        failed = mock.Mock(
            stdout="",
            stderr='column reference "props" is ambiguous',
            returncode=3,
        )
        with mock.patch("subprocess.run", return_value=failed):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.mattermost_post_state(
                    "mattermost-db",
                    "otel-safe",
                    self.runtime(),
                )
        self.assertEqual(raised.exception.code, "command_failed")

    def test_c070_requires_root_only_secret_store_and_legacy_lock_modes(self):
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
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
        health_refs = {
            "9router": "NINEROUTER_HEALTH_URL",
            "kestra": "KESTRA_HEALTH_URL",
            "paperclip": "PAPERCLIP_HEALTH_URL",
            "toolhive": "TOOLHIVE_HEALTH_URL",
            "postgrest": "POSTGREST_HEALTH_URL",
            "mattermost": "MATTERMOST_HEALTH_URL",
            "firecrawl": "FIRECRAWL_HEALTH_URL",
            "searxng": "SEARXNG_HEALTH_URL",
            "observability": "OBSERVABILITY_HEALTH_URL",
        }
        config_init = compose["services"]["config-init"]
        self.assertEqual(
            {key: config_init["environment"][key] for key in health_refs.values()},
            {key: f"${{{key}:?required}}" for key in health_refs.values()},
        )
        command = compose["services"]["config-init"]["command"][0]
        self.assertIn("cat > /config/otel.yml <<EOF", command)
        otel = command.split("cat > /config/otel.yml <<EOF\n", 1)[1].split(
            "\nEOF\n",
            1,
        )[0]
        for service, ref in health_refs.items():
            otel = otel.replace(f"$${{{ref}}}", f"http://{service}.test/health")
        scrape = yaml.safe_load(otel)["receivers"]["prometheus"]["config"][
            "scrape_configs"
        ]
        blackbox = next(row for row in scrape if row["job_name"] == "platform_health")
        targets = {
            row["labels"]["service"]: row["targets"][0]
            for row in blackbox["static_configs"]
        }
        self.assertEqual(
            targets,
            {service: f"http://{service}.test/health" for service in health_refs},
        )
        self.assertEqual(set(targets), set(health_refs))

    def test_config_init_writes_canonical_health_urls_into_otel_config(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        command = compose["services"]["config-init"]["command"][0]
        values = {
            "NINEROUTER_HEALTH_URL": "http://127.0.0.1:20128/api/health",
            "KESTRA_HEALTH_URL": "http://127.0.0.1:18081/health",
            "PAPERCLIP_HEALTH_URL": "http://127.0.0.1:3100/api/health",
            "TOOLHIVE_HEALTH_URL": "http://127.0.0.1:18880/api/openapi.json",
            "POSTGREST_HEALTH_URL": "http://127.0.0.1:18095/ready",
            "MATTERMOST_HEALTH_URL": "http://127.0.0.1:18065/api/v4/system/ping",
            "FIRECRAWL_HEALTH_URL": "http://127.0.0.1:13002/",
            "SEARXNG_HEALTH_URL": "http://127.0.0.1:18088/",
            "OBSERVABILITY_HEALTH_URL": "http://127.0.0.1:13000/api/health",
            "MATTERMOST_ALERT_WEBHOOK_URL": "https://chat.test/hooks/test-only",
        }
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
            config_dir = Path(temporary) / "config"
            # Compose converts $$ to a literal $ before the container shell runs.
            rendered = command.replace("$${", "${").replace("/config", str(config_dir))
            subprocess.run(
                ["/bin/sh", "-ec", rendered],
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, **values},
            )
            otel = yaml.safe_load((config_dir / "otel.yml").read_text())
        blackbox = next(
            row
            for row in otel["receivers"]["prometheus"]["config"]["scrape_configs"]
            if row["job_name"] == "platform_health"
        )
        self.assertEqual(
            {
                row["labels"]["service"]: row["targets"][0]
                for row in blackbox["static_configs"]
            },
            {
                "9router": values["NINEROUTER_HEALTH_URL"],
                "kestra": values["KESTRA_HEALTH_URL"],
                "paperclip": values["PAPERCLIP_HEALTH_URL"],
                "toolhive": values["TOOLHIVE_HEALTH_URL"],
                "postgrest": values["POSTGREST_HEALTH_URL"],
                "mattermost": values["MATTERMOST_HEALTH_URL"],
                "firecrawl": values["FIRECRAWL_HEALTH_URL"],
                "searxng": values["SEARXNG_HEALTH_URL"],
                "observability": values["OBSERVABILITY_HEALTH_URL"],
            },
        )

    def test_node_exporter_avoids_unbounded_systemd_dbus_collector(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        node_exporter = compose["services"]["node-exporter"]
        self.assertNotIn("--collector.systemd", node_exporter["command"])
        self.assertNotIn(
            "/run/dbus/system_bus_socket:/run/dbus/system_bus_socket:ro",
            node_exporter["volumes"],
        )
        self.assertIn("--path.rootfs=/host", node_exporter["command"])

    def test_grafana_double_reconcile_creates_only_once(self):
        runtime = self.runtime()
        state = {
            "datasources": {
                uid: {"id": index + 1, "uid": uid, **expected}
                for index, (uid, expected) in enumerate(runtime.datasources.items())
            },
            "folder": {
                "id": 10,
                "uid": "mte-platform",
                "title": "MTE Platform",
            },
            "accounts": [],
            "creates": 0,
        }

        def call(method, path, auth, supplied_runtime, body=None, allow_status=None):
            self.assertIs(supplied_runtime, runtime)
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
                },
                runtime,
            )
        self.assertTrue(result["idempotent"])
        self.assertEqual(state["creates"], 1)
        self.assertEqual(
            result["first"]["sha256"],
            result["second"]["sha256"],
        )

    def test_grafana_reconcile_reuses_provisioned_folder_by_title(self):
        runtime = self.runtime()
        calls = []
        account = {"id": 20, "name": "mte-observability-prober"}

        def call(method, path, auth, supplied_runtime, body=None, allow_status=None):
            self.assertIs(supplied_runtime, runtime)
            calls.append((method, path))
            if path.startswith("/api/datasources/uid/"):
                uid = path.rsplit("/", 1)[-1]
                expected = runtime.datasources[uid]
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
            result = self.module.reconcile_grafana_once({}, runtime)
        self.assertEqual(result["folderUid"], "generated-uid")
        self.assertNotIn(("POST", "/api/folders"), calls)

    def test_direct_compose_proof_requires_exact_canonical_observability_services(self):
        items = [
            {
                "Name": f"/{service}-1",
                "Labels": {
                    "com.docker.compose.project": self.module.COMPOSE_PROJECT,
                    "com.docker.compose.service": service,
                    "com.docker.compose.config-hash": f"hash-{service}",
                },
            }
            for service in self.module.OBSERVABILITY_COMPOSE_SERVICES
        ]
        proof = self.module.direct_compose_proof(items)
        self.assertEqual(proof["contract"], "direct-docker-compose")
        self.assertEqual(proof["project"], "mte-platform")
        self.assertEqual(
            proof["serviceCount"], len(self.module.OBSERVABILITY_COMPOSE_SERVICES)
        )
        with self.assertRaises(self.module.CanaryError) as missing:
            self.module.direct_compose_proof(items[:-1])
        self.assertEqual(missing.exception.code, "compose_runtime_missing")
        with self.assertRaises(self.module.CanaryError) as duplicate:
            self.module.direct_compose_proof([*items, items[0]])
        self.assertEqual(duplicate.exception.code, "compose_runtime_duplicate")

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

    def test_stable_projection_preserves_only_required_redacted_fingerprints(self):
        bot_fingerprint = "a" * 12
        webhook_fingerprint = "b" * 12
        projected = self.module.stable_projection(
            {
                "fingerprints": {
                    "botToken": bot_fingerprint,
                    "alertWebhook": webhook_fingerprint,
                    "rawToken": "do-not-emit",
                }
            }
        )
        self.assertEqual(
            projected,
            {
                "fingerprints": {
                    "alertWebhook": webhook_fingerprint,
                    "botToken": bot_fingerprint,
                }
            },
        )
        self.module.scan_for_secrets(
            projected,
            {
                "MATTERMOST_BOT_TOKEN": "do-not-emit",
                "MATTERMOST_ALERT_WEBHOOK_URL": "https://example.test/hooks/raw-secret",
            },
        )

    def test_indexed_producer_hashes_bind_profile_reconciler(self):
        with mock.patch.object(
            self.module,
            "installed_producer_hashes",
            return_value={},
        ) as installed:
            self.module.producer_hashes()
        self.assertIn("server-profile-reconcile.py", installed.call_args.args[0])

    def test_atomic_evidence_is_mode_0600(self):
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
            path = Path(temporary) / "evidence" / "canary.json"
            names = []
            original = self.module.tempfile.NamedTemporaryFile

            def temporary_file(*args, **kwargs):
                handle = original(*args, **kwargs)
                names.append(handle.name)
                return handle

            with mock.patch.object(
                self.module.tempfile,
                "NamedTemporaryFile",
                side_effect=temporary_file,
            ):
                self.module.atomic_json(path, {"status": "first"})
                self.module.atomic_json(path, {"status": "passed"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(set(names)), 2)
            self.assertFalse(any(Path(name).exists() for name in names))
            self.assertEqual(
                json.loads(path.read_text())["status"],
                "passed",
            )

    def test_compose_inventory_requires_live_services_and_completed_init(self):
        def labels(service):
            return {
                "com.docker.compose.project": self.module.COMPOSE_PROJECT,
                "com.docker.compose.service": service,
                "com.docker.compose.config-hash": f"hash-{service}",
            }
        running = {
            "Name": "/api-1",
            "Labels": labels("api"),
            "Image": "api@sha256:" + "a" * 64,
            "State": {
                "Status": "running",
                "Running": True,
                "Health": {"Status": "healthy"},
            },
        }
        completed = {
            "Name": "/config-init-1",
            "Labels": labels("config-init"),
            "Image": "init@sha256:" + "b" * 64,
            "State": {"Status": "exited", "Running": False, "ExitCode": 0},
        }
        with (
            mock.patch.object(
                self.module, "run", return_value=mock.Mock(stdout="api\nconfig-init\n")
            ),
            mock.patch.object(
                self.module,
                "docker_inventory",
                return_value=[running, completed],
            ),
        ):
            inventory = self.module.compose_inventory(self.runtime())
        self.assertTrue(inventory["services"]["api"]["running"])
        self.assertEqual(inventory["services"]["api"]["health"], "healthy")
        self.assertEqual(inventory["services"]["config-init"]["exitCode"], 0)

        invalid = (
            {**running, "State": {"Status": "exited", "Running": False}},
            {
                **running,
                "State": {
                    "Status": "running",
                    "Running": True,
                    "Health": {"Status": "unhealthy"},
                },
            },
        )
        for item in invalid:
            with (
                self.subTest(state=item["State"]),
                mock.patch.object(
                    self.module,
                    "run",
                    return_value=mock.Mock(stdout="api\nconfig-init\n"),
                ),
                mock.patch.object(
                    self.module,
                    "docker_inventory",
                    return_value=[item, completed],
                ),
                self.assertRaises(self.module.CanaryError) as raised,
            ):
                self.module.compose_inventory(self.runtime())
            self.assertEqual(
                raised.exception.code, "indexed_compose_runtime_not_ready"
            )

    def test_indexed_reconcile_pass_writes_hash_bound_atomic_evidence(self):
        source_hash = "a" * 64
        gate = {
            "sourceSha256": source_hash,
            "generatorVersion": self.module.GENERATOR_VERSION,
        }
        identity = {
            "compose": {
                "project": "mte-platform",
                "services": {"paperclip": {"configHash": "same"}},
                "componentCount": 1,
                "identitySha256": "b" * 64,
            },
            "provisioner": {"components": []},
            "toolhive": {"binary": "ready"},
            "profileReconcile": {"profiles": []},
        }
        inventory = {
            "sourceGate": gate,
            "identity": identity,
            "identitySha256": "c" * 64,
            "noDuplicates": True,
        }
        provisioned = {
            "ok": True,
            "incomplete": [],
            "canonicalMutationGuard": {"changedKeys": []},
        }
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
            evidence = Path(temporary) / "indexed-pass-2.json"
            with (
                mock.patch.object(
                    self.module,
                    "INDEX_PASS",
                    {1: Path(temporary) / "pass-1.json", 2: evidence},
                ),
                mock.patch.object(self.module, "load_json", return_value={}),
                mock.patch.object(self.module, "dotenv", return_value={}),
                mock.patch.object(self.module, "runtime_values", return_value={}),
                mock.patch.object(
                    self.module, "observability_runtime", return_value=self.runtime()
                ),
                mock.patch.object(
                    self.module, "indexed_inventory", side_effect=[inventory, inventory]
                ),
                mock.patch.object(self.module, "run") as run,
                mock.patch.object(
                    self.module,
                    "run_json_command",
                    side_effect=[provisioned, {"action": "ready"}],
                ),
                mock.patch.object(self.module, "basic_auth", return_value={}),
                mock.patch.object(
                    self.module,
                    "reconcile_grafana_once",
                    return_value={"sha256": "d" * 64},
                ),
                mock.patch.object(
                    self.module, "producer_sha256", return_value="e" * 64
                ),
                mock.patch.object(
                    self.module,
                    "producer_hashes",
                    return_value={"server-observability-canary.py": "e" * 64},
                ),
                mock.patch.object(self.module, "scan_for_secrets"),
            ):
                result = self.module.indexed_reconcile_pass(source_hash, 2)
            self.assertEqual(result["composeActions"], {"paperclip": "unchanged"})
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(evidence.read_text())["sourceGate"], gate)
            self.assertEqual(run.call_args.args[0][-3:], ["up", "-d", "--wait"])

    def test_indexed_inventory_projects_verifier_semantics(self):
        gate = {
            "sourceSha256": "a" * 64,
            "generatorVersion": self.module.GENERATOR_VERSION,
        }
        provisioner = {"ok": True, "incomplete": [], "components": []}
        toolhive = {"binary": "ready", "canary": "ready"}
        profile = {
            "status": "passed",
            "ok": True,
            "profiles": [
                {
                    "profileRef": "coding-daytona-codex",
                    "paperclip": {"status": "ready"},
                    "toolhive": {"status": "ready"},
                    "kestra": {"status": "ready"},
                }
            ],
        }
        with (
            mock.patch.object(self.module, "load_json", return_value={}),
            mock.patch.object(self.module, "exact_hash_gate", return_value=gate),
            mock.patch.object(
                self.module,
                "run_json_command",
                side_effect=[provisioner, toolhive, profile],
            ),
            mock.patch.object(
                self.module,
                "compose_inventory",
                return_value={"componentCount": 1, "services": {}},
            ),
            mock.patch.object(self.module, "scan_for_secrets"),
        ):
            result = self.module.indexed_inventory(
                "a" * 64,
                self.runtime(),
                {},
            )
        identity = result["identity"]
        self.assertEqual(
            identity["toolhive"]["profileBundles"],
            [{"profileRef": "coding-daytona-codex", "status": "ready"}],
        )
        self.assertEqual(
            identity["profileReconcile"]["profiles"],
            [
                {
                    "profileRef": "coding-daytona-codex",
                    "paperclip": True,
                    "toolhive": True,
                    "kestra": True,
                }
            ],
        )

    def test_indexed_finalize_requires_stable_second_pass_and_writes_final(self):
        source_hash = "a" * 64
        gate = {
            "sourceSha256": source_hash,
            "generatorVersion": self.module.GENERATOR_VERSION,
        }
        producer_hashes = {
            "server-observability-canary.py": "b" * 64,
            "server-provision.py": "c" * 64,
            "server-toolhive.py": "d" * 64,
            "server-profile-reconcile.py": "e" * 64,
            "server-config.py": "6" * 64,
        }
        identity = "f" * 64
        first = {
            "sourceGate": gate,
            "producerHashes": producer_hashes,
            "after": {"identitySha256": identity, "noDuplicates": True},
            "provisionerIdentitySha256": "1" * 64,
            "toolhiveIdentitySha256": "2" * 64,
            "grafanaFingerprint": "3" * 64,
        }
        second = {
            "sourceGate": gate,
            "producerHashes": producer_hashes,
            "before": {"identitySha256": identity},
            "after": {
                "identitySha256": identity,
                "noDuplicates": True,
                "identity": {"compose": {"componentCount": 12}},
            },
            "composeActions": {"paperclip": "unchanged"},
            "provisionerIdentitySha256": "1" * 64,
            "toolhiveIdentitySha256": "2" * 64,
            "grafanaFingerprint": "3" * 64,
        }
        with tempfile.TemporaryDirectory(prefix="mte-observability-canary-") as temporary:
            first_path = Path(temporary) / "pass-1.json"
            second_path = Path(temporary) / "pass-2.json"
            final_path = Path(temporary) / "final.json"
            config_path = Path(temporary) / "platform.json"
            manifest_path = Path(temporary) / "manifest.json"
            first_path.write_text(json.dumps(first))
            second_path.write_text(json.dumps(second))
            config_path.write_text("{}")
            manifest_path.write_text("{}")
            with (
                mock.patch.object(
                    self.module, "INDEX_PASS", {1: first_path, 2: second_path}
                ),
                mock.patch.object(self.module, "INDEX_FINAL", final_path),
                mock.patch.object(self.module, "CONFIG", config_path),
                mock.patch.object(self.module, "MANIFEST", manifest_path),
                mock.patch.object(self.module, "exact_hash_gate", return_value=gate),
                mock.patch.object(
                    self.module, "producer_hashes", return_value=producer_hashes
                ),
                mock.patch.object(
                    self.module,
                    "producer_sha256",
                    return_value=producer_hashes["server-observability-canary.py"],
                ),
            ):
                result = self.module.finalize_indexed_idempotency(source_hash)
            self.assertTrue(result["stableComposeIdentity"])
            self.assertTrue(result["secondPassNoChange"])
            self.assertEqual(result["inventoryIdentitySha256"], identity)
            self.assertEqual(final_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
