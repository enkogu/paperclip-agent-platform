import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


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

    def test_discovers_dokploy_container_by_service_label(self):
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
        self.assertFalse(any("compose.project=" in item for item in argv))

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

    def test_duplicate_toolhive_containers_fail_closed(self):
        completed = mock.Mock(stdout="one\ntwo\n")
        with mock.patch.object(self.module, "run", return_value=completed):
            with self.assertRaises(RuntimeError):
                self.module.container()

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
