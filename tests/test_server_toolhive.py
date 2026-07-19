import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_toolhive",
        ROOT / "tools/platform-cli/server-toolhive.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ToolHiveContainerDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_discovers_direct_compose_container_by_service_label(self):
        completed = mock.Mock(stdout="container-id\n")
        with mock.patch.object(
            self.module,
            "run",
            return_value=completed,
        ) as runner:
            self.assertEqual(self.module.container(), "container-id")
        argv = runner.call_args.args[0]
        self.assertIn(
            "label=com.docker.compose.service=toolhive",
            argv,
        )
        self.assertIn("--no-trunc", argv)
        self.assertFalse(any("compose.project=" in item for item in argv))

    def test_install_repairs_only_an_empty_docker_bind_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bin/thv"
            binary.mkdir(parents=True)
            with mock.patch.object(self.module, "BINARY", binary):
                self.module.prepare_binary_destination()
            self.assertFalse(binary.exists())

    def test_install_refuses_a_nonempty_nonfile_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bin/thv"
            binary.mkdir(parents=True)
            (binary / "unexpected").write_text("x")
            with mock.patch.object(self.module, "BINARY", binary):
                with self.assertRaisesRegex(RuntimeError, "not a replaceable file"):
                    self.module.prepare_binary_destination()

    def test_provision_prepulls_pinned_image_before_first_run(self):
        image = "mcp/everything@sha256:" + "1" * 64
        ready = {"status": "running", "toolCount": 7, "echoVerified": True}
        calls = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout="")

        def fake_container(service="toolhive"):
            return {"toolhive": "container-id", "tool-runtime": "runtime-id"}[service]

        with (
            mock.patch.object(
                self.module,
                "canonical",
                return_value={"TOOLHIVE_CANARY_IMAGE": image},
            ),
            mock.patch.object(self.module, "container", side_effect=fake_container),
            mock.patch.object(self.module, "probe_canary", return_value=None),
            mock.patch.object(
                self.module,
                "workload_status",
                return_value={"status": "error"},
            ),
            mock.patch.object(self.module, "wait_canary", return_value=ready),
            mock.patch.object(
                self.module,
                "control_plane_isolation",
                return_value={"transport": "unix"},
            ),
            mock.patch.object(self.module, "run", side_effect=fake_run),
        ):
            self.module.provision()

        pull_index = calls.index(
            ["docker", "exec", "runtime-id", "docker", "pull", image]
        )
        run_index = next(
            index
            for index, argv in enumerate(calls)
            if argv[:4] == ["docker", "exec", "container-id", "thv"] and "run" in argv
        )
        self.assertLess(pull_index, run_index)
        self.assertNotIn("--network", calls[run_index])

    def test_error_status_is_not_ready_even_with_zero_exit(self):
        completed = mock.Mock(
            returncode=0,
            stdout=json.dumps({"name": "everything", "status": "error"}),
        )
        with mock.patch.object(self.module, "run", return_value=completed) as runner:
            self.assertIsNone(self.module.probe_canary("container-id"))
        self.assertEqual(runner.call_count, 1)

    def test_dind_runtime_path_is_shared_and_inner_network_is_not_outer_compose(self):
        compose = (ROOT / "deployment/services/toolhive/compose.yaml").read_text()
        profile = (ROOT / "tools/platform-cli/server-profile-reconcile.py").read_text()
        shared = "- /opt/mte-platform/toolhive/tmp:/opt/mte-platform/toolhive/tmp"
        self.assertEqual(compose.count(shared), 2)
        self.assertNotIn("TOOLHIVE_RUNTIME_NETWORK", profile)

    def test_dind_control_plane_uses_only_a_controller_scoped_unix_socket(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/toolhive/compose.yaml").read_text()
        )
        runtime = compose["services"]["tool-runtime"]
        manager = compose["services"]["toolhive"]

        self.assertEqual(runtime["command"], ["--host=unix:///var/run/docker.sock"])
        self.assertEqual(
            runtime["healthcheck"]["test"],
            ["CMD", "docker", "-H", "unix:///var/run/docker.sock", "info"],
        )
        self.assertEqual(set(runtime["networks"]), {"tool-control"})
        self.assertNotIn("tool-runtime", runtime["networks"])
        self.assertEqual(
            compose["networks"]["tool-control"],
            {"name": "${MTE_TOOLHIVE_CONTROL_NETWORK:?required}"},
        )
        self.assertTrue({"tool-control", "tool-runtime"}.issubset(manager["networks"]))

        holders = {
            service: next(
                volume
                for volume in definition.get("volumes", [])
                if volume.startswith("toolhive-docker-run:")
            )
            for service, definition in compose["services"].items()
            if any(
                volume.startswith("toolhive-docker-run:")
                for volume in definition.get("volumes", [])
            )
        }
        self.assertEqual(
            holders,
            {
                "tool-runtime": "toolhive-docker-run:/var/run",
                "toolhive": "toolhive-docker-run:/var/run:ro",
            },
        )
        self.assertNotIn(
            "2375", (ROOT / "deployment/services/toolhive/compose.yaml").read_text()
        )

    def test_live_isolation_contract_rejects_extra_control_network_member(self):
        runtime_id = "r" * 64
        manager_id = "m" * 64
        intruder_id = "i" * 64
        runtime = {
            "Id": runtime_id,
            "Name": "/tool-runtime",
            "Config": {"Cmd": ["--host=unix:///var/run/docker.sock"], "Labels": {}},
            "NetworkSettings": {"Networks": {"mte-toolhive-control": {}}},
            "Mounts": [{"Name": "mte-toolhive-docker-run", "RW": True}],
        }
        manager = {
            "Id": manager_id,
            "Name": "/toolhive",
            "Config": {"Cmd": ["serve"], "Labels": {}},
            "NetworkSettings": {
                "Networks": {
                    "mte-toolhive-control": {},
                    "mte-tool-runtime": {},
                }
            },
            "Mounts": [{"Name": "mte-toolhive-docker-run", "RW": False}],
        }

        with (
            mock.patch.object(
                self.module,
                "container",
                side_effect=lambda service="toolhive": (
                    runtime_id if service == "tool-runtime" else manager_id
                ),
            ),
            mock.patch.object(
                self.module,
                "docker_inspect",
                return_value=[runtime, manager],
            ),
            mock.patch.object(
                self.module,
                "network_members",
                side_effect=[{runtime_id, manager_id, intruder_id}],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "unauthorized container"):
                self.module.control_plane_isolation()

    def test_live_isolation_contract_proves_negative_ping_from_consumers(self):
        runtime_id = "r" * 64
        manager_id = "m" * 64
        firecrawl_id = "f" * 64
        runtime = {
            "Id": runtime_id,
            "Name": "/tool-runtime",
            "Config": {"Cmd": ["--host=unix:///var/run/docker.sock"], "Labels": {}},
            "NetworkSettings": {"Networks": {"mte-toolhive-control": {}}},
            "Mounts": [{"Name": "mte-toolhive-docker-run", "RW": True}],
        }
        manager = {
            "Id": manager_id,
            "Name": "/toolhive",
            "Config": {"Cmd": ["serve"], "Labels": {}},
            "NetworkSettings": {
                "Networks": {
                    "mte-toolhive-control": {},
                    "mte-tool-runtime": {},
                }
            },
            "Mounts": [{"Name": "mte-toolhive-docker-run", "RW": False}],
        }
        firecrawl = {
            "Id": firecrawl_id,
            "Name": "/mte-platform-api-1",
            "Config": {
                "Cmd": ["node"],
                "Labels": {"com.docker.compose.service": "api"},
                "Env": [
                    "HARNESS_STARTUP_TIMEOUT_MS=30000",
                    "EXTRACT_WORKER_PORT=3004",
                    "NUQ_RABBITMQ_URL=amqp://rabbitmq:5672",
                ],
            },
            "NetworkSettings": {"Networks": {"mte-tool-runtime": {}}},
            "Mounts": [],
        }

        def fake_inspect(*targets):
            if targets == (runtime_id, manager_id):
                return [runtime, manager]
            if targets == (runtime_id, manager_id, firecrawl_id):
                return [runtime, manager, firecrawl]
            if targets == (firecrawl_id,):
                return [firecrawl]
            self.fail(f"unexpected inspect targets: {targets}")

        with (
            mock.patch.object(
                self.module,
                "canonical",
                return_value={"TOOLHIVE_CANARY_IMAGE": "mcp/probe@sha256:" + "1" * 64},
            ),
            mock.patch.object(
                self.module,
                "container",
                side_effect=lambda service="toolhive": (
                    runtime_id if service == "tool-runtime" else manager_id
                ),
            ),
            mock.patch.object(self.module, "docker_inspect", side_effect=fake_inspect),
            mock.patch.object(
                self.module,
                "network_members",
                side_effect=[
                    {runtime_id, manager_id},
                    {manager_id, firecrawl_id},
                ],
            ),
            mock.patch.object(
                self.module,
                "run",
                side_effect=[
                    mock.Mock(
                        stdout=f"{runtime_id}\n{manager_id}\n{firecrawl_id}\n"
                    ),
                    mock.Mock(returncode=0, stdout="", stderr=""),
                ],
            ) as runner,
        ):
            proof = self.module.control_plane_isolation()

        self.assertFalse(proof["tcp2375Reachable"])
        self.assertEqual(proof["negativePingTargets"], ["firecrawl"])
        probe = runner.call_args_list[1].args[0]
        self.assertEqual(
            probe[:5],
            ["docker", "run", "--rm", "--network", f"container:{firecrawl_id}"],
        )
        self.assertIn("--entrypoint", probe)
        self.assertIn("node", probe)
        self.assertIn("http://tool-runtime:2375/_ping", probe[-1])
        self.assertIn("process.exit(42)});", probe[-1])
        self.assertNotIn("process.exit(42)}});", probe[-1])

    def test_duplicate_toolhive_containers_fail_closed(self):
        completed = mock.Mock(stdout="one\ntwo\n")
        with mock.patch.object(self.module, "run", return_value=completed):
            with self.assertRaises(RuntimeError):
                self.module.container()

    def test_canary_image_must_be_content_addressed(self):
        digest = "mcp/everything@sha256:" + "a" * 64
        self.assertEqual(self.module.pinned_image_ref(digest), digest)
        self.assertEqual(self.module.local_image_id(digest), "sha256:" + "a" * 64)
        private_registry = "registry.example:5000/mcp/everything@sha256:" + "b" * 64
        self.assertEqual(self.module.pinned_image_ref(private_registry), private_registry)
        for unsafe in (
            "mcp/everything:latest",
            "mcp/everything@sha256:" + "A" * 64,
            "mcp/everything@sha256:" + "a" * 63,
        ):
            with self.assertRaisesRegex(RuntimeError, "digest pinned"):
                self.module.pinned_image_ref(unsafe)

    def test_profile_workloads_have_a_single_dedicated_owner(self):
        self.assertEqual(
            self.module.PROFILE_WORKLOAD_OWNER,
            "server-profile-reconcile.py",
        )
        self.assertIn(
            "group is an inventory bundle, not\nan authentication identity",
            self.module.__doc__,
        )


if __name__ == "__main__":
    unittest.main()
