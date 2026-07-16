import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-host-dokploy-acceptance.py"


def load_module():
    spec = importlib.util.spec_from_file_location("host_dokploy_acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class HostDokployAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_compose_canary_is_digest_pinned_and_creates_volume_and_network(self):
        rendered = self.module.compose_document(
            "redis@sha256:" + "a" * 64,
            "safe-run",
            "v1",
        )
        self.assertIn("@sha256:" + "a" * 64, rendered)
        self.assertIn("canary-data:/data", rendered)
        self.assertIn("networks:", rendered)
        self.assertIn("com.mte.acceptance.run-id: safe-run", rendered)
        with self.assertRaises(self.module.AcceptanceError):
            self.module.compose_document("redis:latest", "safe-run", "v1")

    def test_full_lifecycle_records_api_operations_hash_change_and_cleanup(self):
        calls = []

        class FakeApi:
            deleted = False

            def request(self, method, path, body=None, retry_login=False):
                calls.append((method, path, body))
                if path == "project.all":
                    return [{"projectId": "project-1", "name": "MTE Platform"}]
                if path.startswith("project.one?"):
                    return {
                        "environments": [
                            {
                                "environmentId": "environment-1",
                                "name": "production",
                                "composes": [] if self.deleted else [],
                            }
                        ]
                    }
                if path == "compose.create":
                    return {"composeId": "compose-acceptance"}
                if path == "compose.delete":
                    self.deleted = True
                    return {"success": True}
                if path.startswith("compose.one?"):
                    return {"composeStatus": "done"}
                if path in {
                    "compose.update",
                    "compose.saveEnvironment",
                    "compose.deploy",
                }:
                    return {"success": True}
                raise AssertionError(path)

        api = FakeApi()

        class FakeDokploy:
            @staticmethod
            def api_key_proof(_base):
                return {
                    "credentialRef": "DOKPLOY_API_TOKEN",
                    "credentialFingerprintSha256": "b" * 64,
                    "apiKeyAuthenticated": True,
                }

            @staticmethod
            def Dokploy(_base, api_key_only=False):
                self.assertTrue(api_key_only)
                return api

            @staticmethod
            def find_environment(_project, _name):
                return {"environmentId": "environment-1"}

            @staticmethod
            def wait_terminal(_api, _compose_id, timeout=0):
                return "done"

            @staticmethod
            def all_dicts(_value):
                return []

        first = {
            "containers": ["one"],
            "volumes": ["vol"],
            "networks": ["net"],
            "containerStates": ["running"],
            "configHashes": ["1" * 64],
        }
        second = {**first, "configHashes": ["2" * 64]}
        cleanup = {
            "remaining": {"containers": 0, "volumes": 0, "networks": 0},
            "noResidualResources": True,
        }
        with (
            mock.patch.object(
                self.module, "DOKPLOY_SCRIPT", ROOT / "tools/platform-cli/server-dokploy.py"
            ),
            mock.patch.object(
                self.module,
                "exact_hash_gate",
                return_value={
                    "sourceSha256": "a" * 64,
                    "generatorVersion": self.module.GENERATOR_VERSION,
                },
            ),
            mock.patch.object(
                self.module,
                "load_json",
                return_value={
                    "spec": {
                        "dokploy": {
                            "baseUrl": "http://dokploy/api",
                            "project": "MTE Platform",
                            "environment": "production",
                        }
                    }
                },
            ),
            mock.patch.object(
                self.module,
                "dotenv",
                side_effect=lambda path: (
                    {
                        "MTE_ACTIVEPIECES_DATA_REDIS_IMAGE": "redis@sha256:" + "c" * 64,
                        "DOKPLOY_API_TOKEN": "hidden-token-not-for-evidence",
                    }
                    if path == self.module.PLATFORM_ENV
                    else {}
                ),
            ),
            mock.patch.object(self.module, "load_dokploy", return_value=FakeDokploy),
            mock.patch.object(
                self.module, "engine_revision", side_effect=[first, second]
            ),
            mock.patch.object(self.module, "cleanup_engine", return_value=cleanup),
            mock.patch.object(self.module, "atomic_json") as writer,
            mock.patch.object(
                self.module.secrets, "token_hex", return_value="abc123def456"
            ),
        ):
            evidence = self.module.apply("a" * 64)
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(
            evidence["C061"]["operations"],
            [
                "list",
                "create",
                "update",
                "status",
                "update",
                "status",
                "delete",
            ],
        )
        self.assertTrue(evidence["C062"]["configHashChanged"])
        self.assertTrue(evidence["C062"]["cleanup"]["noResidualResources"])
        writer.assert_called_once()
        self.assertNotIn("hidden-token", str(evidence))


if __name__ == "__main__":
    unittest.main()
