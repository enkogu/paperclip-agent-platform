from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-baserow.py"
SPEC = importlib.util.spec_from_file_location("server_baserow", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def values(*, generated: bool = True) -> dict[str, str]:
    result = {
        "BASEROW_ADMIN_EMAIL": "operator@example.test",
        "BASEROW_ADMIN_NAME": "MTE Operator",
        "BASEROW_ADMIN_PASSWORD": "admin-secret",
        "BASEROW_DATABASE_NAME": "MTE Agent Registry",
        "BASEROW_DB_HOST": "mte-postgres",
        "BASEROW_DB_NAME": "baserow",
        "BASEROW_DB_PASSWORD": "database-secret",
        "BASEROW_DB_PORT": "5432",
        "BASEROW_DB_USER": "baserow",
        "BASEROW_MCP_ENDPOINT_NAME": "MTE Agent MCP",
        "BASEROW_PAPERCLIP_TOKEN_NAME": "MTE Paperclip Agent",
        "BASEROW_ACTIVEPIECES_TOKEN_NAME": "MTE Activepieces",
        "BASEROW_CPU_LIMIT": "1",
        "BASEROW_MEMORY_LIMIT": "2g",
        "BASEROW_PUBLIC_URL": "https://baserow.example.test",
        "BASEROW_SECRET_KEY": "baserow-secret-key",
        "BASEROW_INTERNAL_URL": "http://127.0.0.1:18085",
        "BASEROW_ORIGIN_PORT": "18085",
        "BASEROW_REDIS_DB": "8",
        "BASEROW_REDIS_CPU_LIMIT": "0.25",
        "BASEROW_REDIS_HOST": "redis",
        "BASEROW_REDIS_MEMORY_LIMIT": "256m",
        "BASEROW_REDIS_PASSWORD": "redis-secret",
        "BASEROW_REDIS_PORT": "6379",
        "BASEROW_TABLE_NAME": "MTE Runtime Canary",
        "BASEROW_WORKSPACE_NAME": "MTE Agents",
        "MTE_BASEROW_BASEROW_IMAGE": module.BASEROW_IMAGE,
        "MTE_BASEROW_REDIS_IMAGE": module.REDIS_IMAGE,
        "MTE_BASEROW_BASEROW_PORT_1_MAPPING": "127.0.0.1:18085:80",
        "PLATFORM_BASE_DOMAIN": "example.test",
    }
    if generated:
        result.update(
            {
                "BASEROW_WORKSPACE_ID": "11",
                "BASEROW_DATABASE_ID": "22",
                "BASEROW_TABLE_ID": "33",
                "BASEROW_PAPERCLIP_TOKEN": "paperclip-token",
                "BASEROW_PAPERCLIP_TOKEN_ID": "44",
                "BASEROW_ACTIVEPIECES_TOKEN": "activepieces-token",
                "BASEROW_ACTIVEPIECES_TOKEN_ID": "55",
                "BASEROW_MCP_ENDPOINT_KEY": "mcp-endpoint-key",
                "BASEROW_MCP_ENDPOINT_ID": "66",
            }
        )
    return result


class BaserowSourceTests(unittest.TestCase):
    def test_images_are_exact_version_and_digest_pins(self) -> None:
        self.assertEqual(
            module.BASEROW_IMAGE,
            "baserow/baserow:2.3.1@sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a",
        )
        self.assertRegex(
            module.REDIS_IMAGE, r"^redis:7\.4\.9-alpine@sha256:[0-9a-f]{64}$"
        )
        self.assertEqual(len(module.LICENSE_SOURCE_SHA256), 64)

    def test_preflight_requires_loopback_and_isolated_credentials(self) -> None:
        result = module.preflight(values())
        self.assertTrue(result["loopbackOnly"])
        self.assertTrue(result["databaseIsolated"])
        self.assertTrue(result["redisIsolated"])
        bad = values()
        bad["MTE_BASEROW_BASEROW_PORT_1_MAPPING"] = "0.0.0.0:18085:80"
        with self.assertRaisesRegex(module.BaserowError, "loopback"):
            module.preflight(bad)

    def test_required_values_reject_shared_secrets_and_unpinned_images(self) -> None:
        bad = values()
        bad["BASEROW_REDIS_PASSWORD"] = bad["BASEROW_DB_PASSWORD"]
        with self.assertRaisesRegex(module.BaserowError, "not_distinct"):
            module.require_values(bad)
        bad = values()
        bad["MTE_BASEROW_BASEROW_IMAGE"] = "baserow/baserow:latest"
        with self.assertRaisesRegex(module.BaserowError, "not_exactly_pinned"):
            module.require_values(bad)

    def test_compose_is_private_and_uses_external_postgres(self) -> None:
        compose = (ROOT / "deployment/services/baserow/compose.yaml").read_text()
        self.assertIn("name: mte-baserow", compose)
        self.assertIn("${MTE_BASEROW_BASEROW_PORT_1_MAPPING:?required}", compose)
        self.assertNotIn("0.0.0.0", compose)
        self.assertIn("ports: []", compose)
        self.assertIn("name: mte-data-plane", compose)
        self.assertIn("external: true", compose)
        self.assertNotRegex(compose, r"(?m)^  postgres:")
        self.assertIn("name: mte-baserow-redis", compose)
        self.assertIn("/api/_health/", compose)
        self.assertIn("${BASEROW_DATABASE_URL:?required}", compose)
        self.assertIn("${BASEROW_REDIS_URL:?required}", compose)
        self.assertNotIn("postgresql://${", compose)
        self.assertNotIn("redis://:${", compose)

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is required")
    def test_compose_config_is_hermetic_with_canonical_placeholders(self) -> None:
        environment = {
            **os.environ,
            "MTE_BASEROW_REDIS_IMAGE": module.REDIS_IMAGE,
            "BASEROW_REDIS_PASSWORD": "redis-placeholder",
            "BASEROW_REDIS_DB": "8",
            "BASEROW_REDIS_CPU_LIMIT": "0.25",
            "BASEROW_REDIS_MEMORY_LIMIT": "256m",
            "MTE_BASEROW_BASEROW_IMAGE": module.BASEROW_IMAGE,
            "BASEROW_PUBLIC_URL": "https://baserow.example.test",
            "BASEROW_SECRET_KEY": "secret-placeholder",
            "BASEROW_DB_USER": "baserow",
            "BASEROW_DB_PASSWORD": "database-placeholder",
            "BASEROW_DB_HOST": "mte-postgres",
            "BASEROW_DB_PORT": "5432",
            "BASEROW_DB_NAME": "baserow",
            "BASEROW_DATABASE_URL": "postgresql://baserow:database-placeholder@mte-postgres:5432/baserow",
            "BASEROW_REDIS_HOST": "redis",
            "BASEROW_REDIS_PORT": "6379",
            "BASEROW_REDIS_URL": "redis://:redis-placeholder@redis:6379/8",
            "MTE_BASEROW_BASEROW_PORT_1_MAPPING": "127.0.0.1:18085:80",
            "BASEROW_CPU_LIMIT": "1",
            "BASEROW_MEMORY_LIMIT": "2g",
        }
        completed = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(ROOT / "deployment/services/baserow/compose.yaml"),
                "config",
                "--format",
                "json",
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rendered = json.loads(completed.stdout)
        mapping = rendered["services"]["baserow"]["ports"][0]
        self.assertEqual(mapping["host_ip"], "127.0.0.1")
        self.assertIn(rendered["services"]["redis"].get("ports"), (None, []))
        self.assertTrue(rendered["networks"]["data-plane"]["external"])

    def test_final_manifest_is_the_direct_deployment_contract(self) -> None:
        path = ROOT / "deployment/services/baserow/compose.yaml"
        self.assertTrue(path.is_file())
        self.assertEqual(path.parent, ROOT / "deployment/services/baserow")
        compose = path.read_text()
        self.assertIn("${MTE_BASEROW_BASEROW_IMAGE:?required}", compose)


class BaserowCanonicalTests(unittest.TestCase):
    def test_canonical_update_is_allowlisted_atomic_and_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "platform.env"
            lock = root / ".platform-env.lock"
            canonical.write_text("KEEP=value\n")
            canonical.chmod(0o600)
            with (
                mock.patch.object(module, "SECRET_ROOT", root),
                mock.patch.object(module, "CANONICAL_ENV", canonical),
                mock.patch.object(module, "CANONICAL_LOCK", lock),
            ):
                result = module.update_canonical({"BASEROW_WORKSPACE_ID": "11"})
            body = canonical.read_text()
            self.assertIn("KEEP=value", body)
            self.assertIn("BASEROW_WORKSPACE_ID=11", body)
            self.assertEqual(stat.S_IMODE(canonical.stat().st_mode), 0o600)
            self.assertEqual(result["changedKeys"], ["BASEROW_WORKSPACE_ID"])
            self.assertEqual(
                result["canonicalSourceSha256"],
                hashlib.sha256(canonical.read_bytes()).hexdigest(),
            )
            with (
                mock.patch.object(module, "SECRET_ROOT", root),
                mock.patch.object(module, "CANONICAL_ENV", canonical),
                mock.patch.object(module, "CANONICAL_LOCK", lock),
            ):
                second = module.update_canonical({"BASEROW_WORKSPACE_ID": "11"})
            self.assertEqual(second["changedKeys"], [])
            with (
                mock.patch.object(module, "SECRET_ROOT", root),
                mock.patch.object(module, "CANONICAL_ENV", canonical),
                mock.patch.object(module, "CANONICAL_LOCK", lock),
                self.assertRaisesRegex(module.BaserowError, "not_allowed"),
            ):
                module.update_canonical({"UNRELATED": "value"})

    def test_evidence_is_root_only_and_contains_no_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "platform.env"
            evidence = root / "baserow-verify.json"
            body = values()
            canonical.write_text(
                "".join(f"{key}={value}\n" for key, value in body.items())
            )
            canonical.chmod(0o600)
            payload = {"kind": "BaserowAcceptance", "status": "passed"}
            with (
                mock.patch.object(module, "CANONICAL_ENV", canonical),
                mock.patch.object(module, "EVIDENCE", evidence),
            ):
                module.write_evidence(payload)
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            self.assertNotIn("paperclip-token", evidence.read_text())
            payload["leak"] = "paperclip-token"
            with (
                mock.patch.object(module, "CANONICAL_ENV", canonical),
                mock.patch.object(module, "EVIDENCE", evidence),
                self.assertRaisesRegex(module.BaserowError, "contains_secret"),
            ):
                module.write_evidence(payload)


class BaserowProvisionTests(unittest.TestCase):
    def test_database_reconcile_uses_isolated_role_and_secret_only_on_stdin(
        self,
    ) -> None:
        seen: dict[str, object] = {}

        def fake_docker(*args: str, input_text: str | None = None) -> str:
            seen["args"] = args
            seen["input"] = input_text
            return '{"role" : true, "database" : true, "owner" : "baserow"}'

        with (
            mock.patch.object(
                module, "postgres_container", return_value="mte-postgres-1"
            ),
            mock.patch.object(module, "docker", side_effect=fake_docker),
        ):
            result = module.ensure_database(values())
        self.assertTrue(result["ownerExact"])
        self.assertNotIn("database-secret", " ".join(seen["args"]))
        self.assertIn("database-secret", str(seen["input"]))
        self.assertIn('CREATE DATABASE "baserow"', str(seen["input"]))

    def test_token_reconcile_creates_and_scopes_each_token_to_database(self) -> None:
        desired = {
            "create": [["database", 22]],
            "read": [["database", 22]],
            "update": [["database", 22]],
            "delete": [["database", 22]],
        }
        calls: list[tuple[str, str, object]] = []
        responses = iter(
            [
                (200, []),
                (
                    200,
                    {
                        "id": 44,
                        "name": "MTE Paperclip Agent",
                        "workspace": 11,
                        "key": "token",
                        "permissions": {},
                    },
                ),
                (
                    200,
                    {
                        "id": 44,
                        "name": "MTE Paperclip Agent",
                        "workspace": 11,
                        "key": "token",
                        "permissions": desired,
                    },
                ),
            ]
        )

        def fake_request(method: str, url: str, **kwargs: object) -> tuple[int, object]:
            calls.append((method, url, kwargs.get("body")))
            return next(responses)

        with mock.patch.object(module, "request_json", side_effect=fake_request):
            token = module.ensure_database_token(
                values(),
                "jwt",
                workspace_id=11,
                database_id=22,
                name="MTE Paperclip Agent",
            )
        self.assertEqual(token["key"], "token")
        self.assertEqual(calls[1][2], {"name": "MTE Paperclip Agent", "workspace": 11})
        self.assertEqual(calls[2][2], {"permissions": desired})

    def test_provision_persists_two_distinct_tokens_and_mcp_key(self) -> None:
        v = values(generated=False)
        with (
            mock.patch.object(module, "wait_health"),
            mock.patch.object(module, "admin_session", return_value="jwt"),
            mock.patch.object(module, "ensure_workspace", return_value={"id": 11}),
            mock.patch.object(
                module, "ensure_database_application", return_value={"id": 22}
            ),
            mock.patch.object(module, "ensure_table", return_value={"id": 33}),
            mock.patch.object(
                module,
                "ensure_database_token",
                side_effect=[
                    {"id": 44, "key": "paperclip"},
                    {"id": 55, "key": "activepieces"},
                ],
            ) as token_reconcile,
            mock.patch.object(
                module, "ensure_mcp_endpoint", return_value={"id": 66, "key": "mcp"}
            ),
            mock.patch.object(
                module,
                "update_canonical",
                return_value={"changedKeys": [], "canonicalSourceSha256": "a" * 64},
            ) as update,
        ):
            result = module.provision(v)
        self.assertTrue(result["tokensDistinct"])
        self.assertEqual(token_reconcile.call_count, 2)
        persisted = update.call_args.args[0]
        self.assertEqual(persisted["BASEROW_PAPERCLIP_TOKEN"], "paperclip")
        self.assertEqual(persisted["BASEROW_ACTIVEPIECES_TOKEN"], "activepieces")
        self.assertEqual(persisted["BASEROW_MCP_ENDPOINT_KEY"], "mcp")


class BaserowProofTests(unittest.TestCase):
    def test_mcp_probe_requires_initialize_and_all_ose_tools(self) -> None:
        class FakeSession:
            def __init__(self, url: str):
                self.url = url

            def start(self) -> None:
                return None

            def next(self) -> tuple[str, str]:
                return "endpoint", "/mcp/messages/?session_id=1"

            def close(self) -> None:
                return None

        tools = [{"name": name} for name in sorted(module.EXPECTED_MCP_TOOLS)]
        with (
            mock.patch.object(module, "SSESession", FakeSession),
            mock.patch.object(module, "mcp_post", return_value=202) as post,
            mock.patch.object(
                module,
                "wait_jsonrpc",
                side_effect=[
                    {"result": {"protocolVersion": "2024-11-05"}},
                    {"result": {"tools": tools}},
                ],
            ),
        ):
            result = module.mcp_probe(values())
        self.assertTrue(result["initializeOk"])
        self.assertTrue(result["toolsListOk"])
        self.assertEqual(set(result["toolNames"]), module.EXPECTED_MCP_TOOLS)
        self.assertEqual(post.call_count, 3)

    def test_restart_canary_proves_crud_persistence_and_404_cleanup(self) -> None:
        responses = iter(
            [
                (200, {"id": 77, "Value": "mte"}),
                (200, {"id": 77, "Value": "mte"}),
                (200, {"id": 77, "Value": "mte-updated"}),
                (200, {"id": 77, "Value": "mte-updated"}),
                (204, None),
                (404, {"error": "not_found"}),
            ]
        )

        def fake_request(method: str, url: str, **kwargs: object) -> tuple[int, object]:
            status, payload = next(responses)
            body = kwargs.get("body")
            if method == "POST" and isinstance(body, dict):
                payload["Value"] = body["Value"]
            if method == "GET" and status == 200 and isinstance(payload, dict):
                if payload.get("Value") == "mte":
                    payload["Value"] = marker["created"]
                elif payload.get("Value") == "mte-updated":
                    payload["Value"] = marker["updated"]
            if method == "PATCH" and isinstance(body, dict):
                payload["Value"] = body["Value"]
            return status, payload

        marker: dict[str, str] = {}

        def fake_uuid() -> str:
            marker["created"] = "mte-baserow-fixed"
            marker["updated"] = "mte-baserow-fixed-updated"
            return "fixed"

        docker_results = iter(
            ["container-id", "started-before", "restarted", "started-after"]
        )
        with (
            mock.patch.object(module.uuid, "uuid4", side_effect=fake_uuid),
            mock.patch.object(
                module, "compose_container", return_value="mte-baserow-baserow-1"
            ),
            mock.patch.object(
                module, "docker", side_effect=lambda *args: next(docker_results)
            ),
            mock.patch.object(module, "wait_health"),
            mock.patch.object(module, "request_json", side_effect=fake_request),
        ):
            result = module.restart_persistence_canary(values())
        self.assertTrue(result["restartObserved"])
        self.assertTrue(result["persistenceVerified"])
        self.assertTrue(result["postDeleteStatus404"])
        self.assertTrue(result["cleanupCompleted"])
        self.assertEqual(result["rowId"], 77)

    def test_verify_envelope_is_hash_bound_and_secret_free(self) -> None:
        gate = {
            "canonicalSourceSha256": "a" * 64,
            "producerSha256": "b" * 64,
            "canonicalMode": "0600",
        }
        with (
            mock.patch.object(module, "wait_health"),
            mock.patch.object(
                module, "runtime_distribution", return_value={"name": "Baserow OSE"}
            ),
            mock.patch.object(
                module,
                "rest_probe",
                return_value={
                    "ok": True,
                    "tokensDistinct": True,
                    "tokenFingerprints": {
                        "paperclip": "c" * 64,
                        "activepieces": "d" * 64,
                    },
                },
            ),
            mock.patch.object(
                module,
                "mcp_probe",
                return_value={"ok": True, "keyFingerprint": "e" * 64},
            ),
            mock.patch.object(
                module,
                "restart_persistence_canary",
                return_value={
                    "ok": True,
                    "databaseId": 22,
                    "tableId": 33,
                    "rowId": 77,
                    "markerSha256": "f" * 64,
                    "restartObserved": True,
                    "persistenceVerified": True,
                    "postDeleteStatus": 404,
                    "cleanupCompleted": True,
                },
            ),
            mock.patch.object(module, "source_gate", return_value=gate),
        ):
            result = module.verify(values(), restart_canary=True)
        self.assertEqual(result["kind"], "BaserowAcceptance")
        self.assertEqual(result["apiVersion"], "mte.example.test/v1")
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["ok"])
        self.assertEqual(result["canonicalSourceSha256"], "a" * 64)
        self.assertEqual(result["producerSha256"], "b" * 64)
        self.assertFalse(result["secrets"]["rawValuesIncluded"])
        self.assertNotIn("paperclip-token", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
