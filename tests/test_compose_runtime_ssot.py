import importlib.util
import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = tuple(sorted((ROOT / "deployment/services").glob("*/compose.yaml")))
CANONICAL_REF = re.compile(r"^\$\{[A-Z][A-Z0-9_]*:\?required\}$")


def load_server_config():
    path = ROOT / "tools/platform-cli/server-config.py"
    spec = importlib.util.spec_from_file_location("server_config_ssot", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load server-config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ComposeRuntimeSsotTests(unittest.TestCase):
    def test_container_runtime_uses_only_canonical_images_without_source_builds(self):
        self.assertTrue(COMPOSE_FILES)
        for path in COMPOSE_FILES:
            document = yaml.safe_load(path.read_text())
            for service_name, service in document["services"].items():
                with self.subTest(path=path.relative_to(ROOT), service=service_name):
                    self.assertNotIn("build", service)
                    self.assertRegex(str(service.get("image", "")), CANONICAL_REF)

    def test_all_runtime_limits_healthchecks_ports_and_logging_are_canonical(self):
        self.assertTrue(COMPOSE_FILES)
        for path in COMPOSE_FILES:
            with self.subTest(path=path.relative_to(ROOT)):
                document = yaml.safe_load(path.read_text())
                services = document["services"]
                self.assertIsInstance(services, dict)
                for service_name, service in services.items():
                    self.assertIsInstance(service, dict, service_name)
                    for field in ("cpus", "mem_limit", "pids_limit"):
                        value = service.get(field)
                        if value is not None:
                            self.assertRegex(str(value), CANONICAL_REF, field)
                    for field in ("interval", "timeout", "retries", "start_period"):
                        value = (service.get("healthcheck") or {}).get(field)
                        if value is not None:
                            self.assertRegex(str(value), CANONICAL_REF, field)
                    for port in service.get("ports") or []:
                        self.assertRegex(str(port), CANONICAL_REF, "ports")
                    logging = service.get("logging")
                    self.assertIsInstance(logging, dict, service_name)
                    self.assertEqual(logging.get("driver"), "json-file")
                    self.assertEqual(
                        logging.get("options"),
                        {
                            "max-size": "${MTE_DOCKER_LOG_MAX_SIZE:?required}",
                            "max-file": "${MTE_DOCKER_LOG_MAX_FILES:?required}",
                        }
                        | (
                            {"compress": "true"}
                            if path.parent.name == "firecrawl"
                            else {}
                        ),
                    )

    def test_shared_runtime_classes_are_seeded_in_the_canonical_environment(self):
        seeds = load_server_config().ONE_TIME_MIGRATION_SEEDS
        required = {
            *(
                f"MTE_PIDS_{name}_LIMIT"
                for name in (
                    "INIT",
                    "LIGHTWEIGHT",
                    "DATASTORE",
                    "SERVICE",
                    "DOCKER",
                    "APP",
                    "BROWSER",
                    "HEAVY",
                )
            ),
            *(
                f"MTE_HEALTHCHECK_{speed}_{field}"
                for speed in (
                    "FAST",
                    "STANDARD",
                    "SLOW",
                )
                for field in ("INTERVAL", "TIMEOUT", "RETRIES", "START_PERIOD")
            ),
            "MTE_DOCKER_LOG_MAX_SIZE",
            "MTE_DOCKER_LOG_MAX_FILES",
            "MTE_OBSERVABILITY_VICTORIAMETRICS_RETENTION_PERIOD",
            "MTE_OBSERVABILITY_VICTORIALOGS_RETENTION_PERIOD",
            "MTE_OBSERVABILITY_VICTORIATRACES_RETENTION_PERIOD",
            "MTE_TOOL_RUNTIME_NETWORK",
            "MTE_TOOLHIVE_CONTROL_NETWORK",
        }
        self.assertTrue(required.issubset(seeds), sorted(required - set(seeds)))

    def test_tool_runtime_network_names_have_one_canonical_owner(self):
        firecrawl = yaml.safe_load(
            (ROOT / "deployment/services/firecrawl/compose.yaml").read_text()
        )
        toolhive = yaml.safe_load(
            (ROOT / "deployment/services/toolhive/compose.yaml").read_text()
        )
        self.assertEqual(
            firecrawl["networks"]["tool-runtime"]["name"],
            "${MTE_TOOL_RUNTIME_NETWORK:?required}",
        )
        self.assertEqual(
            toolhive["networks"]["tool-runtime"]["name"],
            "${MTE_TOOL_RUNTIME_NETWORK:?required}",
        )
        self.assertEqual(
            toolhive["networks"]["tool-control"]["name"],
            "${MTE_TOOLHIVE_CONTROL_NETWORK:?required}",
        )

    def test_mattermost_dsn_uses_canonical_database_endpoint(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/mattermost/compose.yaml").read_text()
        )
        datasource = compose["services"]["mattermost"]["environment"][
            "MM_SQLSETTINGS_DATASOURCE"
        ]
        self.assertEqual(
            datasource,
            "postgres://${MATTERMOST_DB_USER:?required}:"
            "${MATTERMOST_DB_PASSWORD:?required}@${MATTERMOST_DB_HOST:?required}:"
            "${MATTERMOST_DB_PORT:?required}/${MATTERMOST_DB_NAME:?required}"
            "?sslmode=disable&connect_timeout=10",
        )
        self.assertNotIn("mte-mattermost-postgres:5432", datasource)

    def test_firecrawl_has_no_unreferenced_duplicate_environment_extension(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/firecrawl/compose.yaml").read_text()
        )
        self.assertNotIn("x-firecrawl-env", compose)

    def test_daytona_api_healthcheck_matches_platform_health_contract(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/daytona/compose.yaml").read_text()
        )
        healthcheck = compose["services"]["api"]["healthcheck"]
        test = healthcheck["test"]
        self.assertEqual(test[:3], ["CMD", "node", "-e"])
        self.assertIn("127.0.0.1:$${process.env.PORT}/api/config", test[3])
        self.assertNotIn("API_KEY", test[3])
        self.assertEqual(
            {
                key: healthcheck[key]
                for key in (
                    "interval",
                    "timeout",
                    "retries",
                    "start_period",
                )
            },
            {
                "interval": "${MTE_HEALTHCHECK_STANDARD_INTERVAL:?required}",
                "timeout": "${MTE_HEALTHCHECK_STANDARD_TIMEOUT:?required}",
                "retries": "${MTE_HEALTHCHECK_STANDARD_RETRIES:?required}",
                "start_period": "${MTE_HEALTHCHECK_STANDARD_START_PERIOD:?required}",
            },
        )

    def test_daytona_internal_endpoints_are_derived_not_operator_defaults(self):
        server_config = load_server_config()
        values = dict(server_config.ONE_TIME_MIGRATION_SEEDS)
        server_config.apply_daytona_internal_projections(values)
        self.assertTrue(
            server_config.DAYTONA_INTERNAL_DERIVED_KEYS
            <= server_config.DERIVED_VALUE_KEYS
        )
        self.assertEqual(values["MTE_DAYTONA_INTERNAL_API_URL"], "http://api:3000/api")
        self.assertEqual(
            values["MTE_DAYTONA_PROXY_DOMAIN"],
            "mte-daytona-proxy:4000",
        )
        self.assertEqual(
            values["MTE_DAYTONA_PROXY_TEMPLATE_URL"],
            "http://{{PORT}}-{{sandboxId}}.proxy.localhost:3410",
        )
        daytona = yaml.safe_load(
            (ROOT / "deployment/services/daytona/compose.yaml").read_text()
        )
        self.assertEqual(
            set(daytona["services"]["proxy"]["networks"]),
            {"daytona", "paperclip-api"},
        )
        compose_seeds = yaml.safe_load(
            (ROOT / "config/compose-seeds.lock.json").read_text()
        )["seeds"]
        self.assertTrue(
            server_config.DAYTONA_INTERNAL_DERIVED_KEYS.isdisjoint(compose_seeds)
        )

    def test_observability_otlp_route_has_exact_permanent_membership(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        services = compose["services"]
        collector = services["otel-collector"]
        self.assertNotIn("network_mode", collector)
        self.assertEqual(collector["networks"], ["observability"])
        self.assertEqual(
            collector["ports"],
            ["${MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_1_MAPPING:?required}"],
        )
        compose_seeds = yaml.safe_load(
            (ROOT / "config/compose-seeds.lock.json").read_text()
        )["seeds"]
        self.assertEqual(
            compose_seeds["MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_1_MAPPING"],
            "127.0.0.1:4318:4318",
        )
        self.assertIn(
            "MTE_OBSERVABILITY_OTEL_COLLECTOR_PORT_1_MAPPING",
            load_server_config().REVIEWED_COMPOSE_SEED_MIGRATIONS,
        )
        self.assertEqual(
            load_server_config().ONE_TIME_MIGRATION_SEEDS[
                "OBSERVABILITY_OTLP_HTTP_URL"
            ],
            "http://127.0.0.1:4318",
        )
        self.assertEqual(
            collector["extra_hosts"],
            ["host.docker.internal:host-gateway"],
        )
        permanent_members = {
            name
            for name, service in services.items()
            if "observability" in (service.get("networks") or [])
        }
        self.assertEqual(
            permanent_members,
            {
                "victoriametrics",
                "victorialogs",
                "victoriatraces",
                "cadvisor",
                "otel-collector",
                "alertmanager",
                "vmalert",
                "grafana",
            },
        )
        self.assertTrue({"paperclip", "daytona-runner"}.isdisjoint(services))

    def test_alertmanager_reaches_mattermost_on_existing_private_network(self):
        observability = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        mattermost = yaml.safe_load(
            (ROOT / "deployment/services/mattermost/compose.yaml").read_text()
        )

        self.assertEqual(
            set(observability["services"]["alertmanager"]["networks"]),
            {"observability", "mattermost-data"},
        )
        self.assertIn(
            "mattermost-data", mattermost["services"]["mattermost"]["networks"]
        )
        self.assertEqual(
            observability["networks"]["mattermost-data"],
            {"name": "mte-mattermost-data", "external": True},
        )
        self.assertEqual(
            mattermost["networks"]["mattermost-data"]["name"],
            "mte-mattermost-data",
        )
        self.assertTrue(
            all(
                str(port).startswith("${MTE_MATTERMOST_")
                for port in mattermost["services"]["mattermost"]["ports"]
            )
        )
        compose_seeds = yaml.safe_load(
            (ROOT / "config/compose-seeds.lock.json").read_text()
        )["seeds"]
        self.assertTrue(
            compose_seeds["MTE_MATTERMOST_MATTERMOST_PORT_1_MAPPING"].startswith(
                "127.0.0.1:"
            )
        )

    def test_observability_collector_uses_container_dns_and_host_gateway_routes(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/observability/compose.yaml").read_text()
        )
        services = compose["services"]
        command = services["config-init"]["command"][0]
        otel_text = command.split("cat > /config/otel.yml <<EOF\n", 1)[1].split(
            "\nEOF\n",
            1,
        )[0]
        for service, ref in {
            "9router": "NINEROUTER_HEALTH_URL",
            "kestra": "KESTRA_HEALTH_URL",
            "paperclip": "PAPERCLIP_HEALTH_URL",
            "toolhive": "TOOLHIVE_HEALTH_URL",
            "postgrest": "POSTGREST_HEALTH_URL",
            "mattermost": "MATTERMOST_HEALTH_URL",
            "firecrawl": "FIRECRAWL_HEALTH_URL",
            "searxng": "SEARXNG_HEALTH_URL",
            "observability": "OBSERVABILITY_HEALTH_URL",
        }.items():
            otel_text = otel_text.replace(
                f"$${{{ref}}}", f"http://{service}.test/health"
            )
        otel = yaml.safe_load(otel_text)
        protocols = otel["receivers"]["otlp"]["protocols"]
        self.assertEqual(protocols["grpc"]["endpoint"], "0.0.0.0:4317")
        self.assertEqual(protocols["http"]["endpoint"], "0.0.0.0:4318")
        exporters = otel["exporters"]
        self.assertEqual(
            exporters["otlphttp/victoriametrics"]["metrics_endpoint"],
            "http://victoriametrics:8428/opentelemetry/v1/metrics",
        )
        self.assertEqual(
            exporters["otlphttp/victorialogs"]["logs_endpoint"],
            "http://victorialogs:9428/insert/opentelemetry/v1/logs",
        )
        self.assertEqual(
            exporters["otlphttp/victoriatraces"]["traces_endpoint"],
            "http://victoriatraces:10428/insert/opentelemetry/v1/traces",
        )
        scrape = otel["receivers"]["prometheus"]["config"]["scrape_configs"]
        by_job = {row["job_name"]: row for row in scrape}
        self.assertEqual(
            by_job["node"]["static_configs"][0]["targets"],
            ["host.docker.internal:19100"],
        )
        self.assertEqual(
            by_job["containers"]["static_configs"][0]["targets"],
            ["cadvisor:8080"],
        )
        self.assertEqual(
            by_job["platform_health"]["relabel_configs"][-1]["replacement"],
            "host.docker.internal:19115",
        )
        self.assertIn(
            "--web.listen-address=host.docker.internal:19115",
            services["blackbox-exporter"]["command"],
        )
        self.assertIn(
            "--web.listen-address=host.docker.internal:19100",
            services["node-exporter"]["command"],
        )
        self.assertEqual(
            services["blackbox-exporter"]["extra_hosts"],
            ["host.docker.internal:host-gateway"],
        )
        self.assertEqual(
            services["node-exporter"]["extra_hosts"],
            ["host.docker.internal:host-gateway"],
        )


if __name__ == "__main__":
    unittest.main()
