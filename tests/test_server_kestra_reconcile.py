from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock
import urllib.parse

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_kestra_reconcile",
        ROOT / "tools/platform-cli/server-kestra-reconcile.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeKestra:
    def __init__(self) -> None:
        self.flows: dict[tuple[str, str], dict] = {}
        self.kv: dict[str, dict] = {}
        self.calls: list[dict] = []
        self.clock = datetime.datetime(2026, 7, 15, tzinfo=datetime.timezone.utc)
        self.unstable_reads = False

    def now(self) -> str:
        self.clock += datetime.timedelta(seconds=1)
        return self.clock.isoformat()

    @staticmethod
    def clone(value):
        return json.loads(json.dumps(value))

    def request(
        self,
        base,
        _headers,
        method,
        path,
        *,
        body=None,
        content_type=None,
        allow_status=None,
        timeout_seconds=None,
    ):
        self.calls.append(
            {
                "base": base,
                "method": method,
                "path": path,
                "body": body,
                "contentType": content_type,
                "timeoutSeconds": timeout_seconds,
            }
        )
        clean = urllib.parse.urlsplit(path).path
        parts = clean.strip("/").split("/")
        if clean == "/api/v1/main/flows" and method == "POST":
            if content_type != "application/x-yaml":
                raise AssertionError(f"unexpected flow content type: {content_type}")
            parsed = yaml.safe_load(body.decode())
            identity = (parsed["namespace"], parsed["id"])
            self.flows[identity] = {
                "id": identity[1],
                "namespace": identity[0],
                "revision": 1,
                "updated": self.now(),
                "source": body.decode(),
                "deleted": False,
                "draft": False,
            }
            return 200, self.clone(self.flows[identity])
        if len(parts) >= 6 and parts[3] == "flows":
            namespace = urllib.parse.unquote(parts[4])
            flow_id = urllib.parse.unquote(parts[5])
            identity = (namespace, flow_id)
            if method == "GET":
                if identity not in self.flows:
                    return 404, None
                if self.unstable_reads:
                    self.flows[identity]["updated"] = self.now()
                return 200, self.clone(self.flows[identity])
            if method == "PUT":
                if content_type != "application/x-yaml":
                    raise AssertionError(
                        f"unexpected flow content type: {content_type}"
                    )
                current = self.flows[identity]
                current.update(
                    {
                        "revision": current["revision"] + 1,
                        "updated": self.now(),
                        "source": body.decode(),
                    }
                )
                return 200, self.clone(current)
        if len(parts) >= 7 and parts[3] == "namespaces" and parts[5] == "kv":
            namespace = urllib.parse.unquote(parts[4])
            key = urllib.parse.unquote(parts[6])
            self.assert_namespace(namespace)
            if method == "GET":
                if key not in self.kv:
                    return 404, None
                return 200, self.clone(self.kv[key])
            if method == "PUT":
                if content_type != "text/plain":
                    raise AssertionError(f"unexpected KV content type: {content_type}")
                current = self.kv.get(key)
                self.kv[key] = {
                    "type": "JSON",
                    "value": json.loads(body),
                    "revision": 1 if current is None else current["revision"] + 1,
                    "updated": self.now(),
                }
                return 200, None
        allowed = sorted(allow_status or [])
        raise AssertionError(f"unexpected request: {method} {path} allowed={allowed}")

    @staticmethod
    def assert_namespace(namespace: str) -> None:
        if namespace != "mte.platform":
            raise AssertionError(f"unexpected namespace: {namespace}")


class KestraReconcileTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory(prefix="mte-kestra-reconcile-")
        self.root = Path(self.temp.name) / "platform"
        self.secrets = Path(self.temp.name) / "secrets"
        self.root.mkdir()
        self.secrets.mkdir()
        self.canonical = self.secrets / "platform.env"
        self.canonical.write_text(
            "KESTRA_ADMIN_USER=operator\n"
            "KESTRA_ADMIN_PASSWORD=unit-only-kestra-secret\n"
            "KESTRA_LOOPBACK_HOST=127.0.0.1\n"
            "KESTRA_ORIGIN_PORT=18082\n"
            "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS=60\n"
        )
        self.canonical.chmod(0o600)
        lock = self.root / "platform.lock.yaml"
        lock.write_text(
            "apiVersion: micro-task-engine/v1alpha1\n"
            "kind: PlatformLock\n"
            "spec:\n"
            "  kestra: 1.3.27\n"
        )
        flow_dir = self.root / "workflows/kestra"
        flow_dir.mkdir(parents=True)
        identities = {
            "control-plane.yaml": ("control-plane", "mte.platform"),
            "paperclip-runtime.yaml": (
                "paperclip-runtime",
                "micro_task_engine.prototype",
            ),
            "platform-canary.yaml": ("platform-canary", "system.health"),
            "paperclip-github-e2e.yaml": (
                "paperclip-github-e2e",
                "micro_task_engine.e2e",
            ),
        }
        for filename, (flow_id, namespace) in identities.items():
            (flow_dir / filename).write_text(
                f"id: {flow_id}\n"
                f"namespace: {namespace}\n"
                "tasks:\n"
                "  - id: test\n"
                "    type: io.kestra.plugin.core.log.Log\n"
                "    message: test\n"
            )
        source_dir = self.root / "config/profiles"
        runtime_dir = self.root / "runtime/profiles"
        source_dir.mkdir(parents=True)
        runtime_dir.mkdir(parents=True)
        catalog = yaml.safe_load((ROOT / "config/profiles/catalog.yaml").read_text())

        def render(value):
            if isinstance(value, dict):
                return {key: render(nested) for key, nested in value.items()}
            if isinstance(value, list):
                return [render(nested) for nested in value]
            if isinstance(value, str):
                return re.sub(r"\$\{[^}]+\}", "rendered-unit-value", value)
            return value

        (source_dir / "catalog.yaml").write_text(
            yaml.safe_dump(catalog, sort_keys=False)
        )
        (runtime_dir / "profiles.yaml").write_text(
            yaml.safe_dump(render(catalog), sort_keys=False)
        )
        self.provision_evidence = self.root / "evidence/kestra-reconcile.json"
        self.verify_evidence = self.root / "evidence/kestra-reconcile-verify.json"
        self.fake = FakeKestra()
        self.patches = (
            mock.patch.object(self.module, "ROOT", self.root),
            mock.patch.object(self.module, "SECRET_ROOT", self.secrets),
            mock.patch.object(self.module, "CANONICAL_ENV", self.canonical),
            mock.patch.object(self.module, "PLATFORM_LOCK", lock),
            mock.patch.object(
                self.module, "PROVISION_EVIDENCE", self.provision_evidence
            ),
            mock.patch.object(self.module, "VERIFY_EVIDENCE", self.verify_evidence),
            mock.patch.object(self.module, "request", side_effect=self.fake.request),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def test_provision_then_verify_is_exact_noop_and_secret_free(self):
        provision = self.module.execute("provision")
        self.assertEqual(provision["firstPass"]["mutationCount"], 6)
        self.assertEqual(provision["secondPass"]["mutationCount"], 0)
        self.assertTrue(provision["secondPass"]["noOp"])
        self.assertTrue(provision["stableRemoteState"])
        self.assertEqual(len(provision["flowSourceSet"]), 4)
        self.assertTrue(
            all(
                row["sourceRef"].startswith("workflows/kestra/")
                for row in provision["flowSourceSet"]
            )
        )
        self.assertEqual(
            provision["profileRefs"], list(self.module.EXPECTED_PROFILE_REFS)
        )
        self.assertEqual(stat.S_IMODE(self.provision_evidence.stat().st_mode), 0o600)
        self.assertNotIn("unit-only-kestra-secret", self.provision_evidence.read_text())
        self.assertEqual(
            sorted(self.fake.kv),
            [self.module.FLOW_CATALOG_KEY, self.module.PROFILE_CATALOG_KEY],
        )
        self.assertEqual(
            self.fake.kv[self.module.PROFILE_CATALOG_KEY]["value"]["namespace"],
            "mte.platform",
        )
        self.assertTrue(
            all(
                call["base"] == "http://127.0.0.1:18082"
                and call["timeoutSeconds"] == 60
                for call in self.fake.calls
            )
        )
        self.assertEqual(
            provision["connection"],
            {
                "scheme": "http",
                "hostRef": "KESTRA_LOOPBACK_HOST",
                "portRef": "KESTRA_ORIGIN_PORT",
                "timeoutSecondsRef": "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS",
                "loopbackOnly": True,
            },
        )

        verify = self.module.execute("verify")
        self.assertEqual(verify["firstPass"]["mutationCount"], 0)
        self.assertEqual(verify["secondPass"]["mutationCount"], 0)
        self.assertTrue(verify["stableRemoteState"])
        self.assertEqual(
            verify["subjectProvisionEvidence"],
            {
                "path": str(self.provision_evidence),
                "sha256": hashlib.sha256(
                    self.provision_evidence.read_bytes()
                ).hexdigest(),
            },
        )
        self.assertEqual(stat.S_IMODE(self.verify_evidence.stat().st_mode), 0o600)
        self.assertNotIn("unit-only-kestra-secret", self.verify_evidence.read_text())

    def test_compose_defers_canonical_workflow_lifecycle_to_rest_reconciler(self):
        compose = yaml.safe_load(
            (ROOT / "deployment/services/kestra/compose.yaml").read_text()
        )
        service = compose["services"]["kestra"]
        self.assertNotIn("--flow-path", service["command"])
        self.assertNotIn("/app/flows", service["command"])
        self.assertFalse(
            any("workflows/kestra" in volume for volume in service["volumes"])
        )

        flow_dir = self.root / "workflows/kestra"
        canonical = flow_dir / "platform-canary.yaml"
        canonical.write_text(canonical.read_text() + "description: canonical-source\n")
        self.assertEqual(self.module.flow_directory(), flow_dir)
        desired = self.module.load_flows()
        canary = next(row for row in desired if row["id"] == "platform-canary")
        self.assertEqual(canary["sourcePath"], canonical)
        self.assertIn("description: canonical-source", canary["source"])

        created = self.module.execute("provision")
        self.assertEqual(created["firstPass"]["mutationCount"], 6)
        self.assertEqual(created["secondPass"]["mutationCount"], 0)
        flow_writes = [
            call
            for call in self.fake.calls
            if call["method"] in {"POST", "PUT"}
            and urllib.parse.urlsplit(call["path"]).path.startswith(
                "/api/v1/main/flows"
            )
        ]
        self.assertEqual([call["method"] for call in flow_writes], ["POST"] * 4)
        self.assertTrue(
            any(
                b"description: canonical-source" in (call["body"] or b"")
                for call in flow_writes
            )
        )

        self.fake.calls.clear()
        unchanged = self.module.execute("provision")
        self.assertEqual(unchanged["firstPass"]["mutationCount"], 0)
        self.assertEqual(unchanged["secondPass"]["mutationCount"], 0)
        self.assertFalse(
            any(
                call["method"] in {"POST", "PUT"}
                and urllib.parse.urlsplit(call["path"]).path.startswith(
                    "/api/v1/main/flows"
                )
                for call in self.fake.calls
            )
        )

        canonical.write_text(canonical.read_text() + "labels: {release: updated}\n")
        self.fake.calls.clear()
        updated = self.module.execute("provision")
        self.assertEqual(updated["secondPass"]["mutationCount"], 0)
        flow_writes = [
            call
            for call in self.fake.calls
            if call["method"] in {"POST", "PUT"}
            and urllib.parse.urlsplit(call["path"]).path.startswith(
                "/api/v1/main/flows"
            )
        ]
        self.assertEqual(
            [
                (call["method"], urllib.parse.urlsplit(call["path"]).path)
                for call in flow_writes
            ],
            [("PUT", "/api/v1/main/flows/system.health/platform-canary")],
        )

    def test_single_flow_drift_updates_only_flow_and_derived_catalog(self):
        self.module.execute("provision")
        identity = ("micro_task_engine.prototype", "paperclip-runtime")
        self.fake.flows[identity]["source"] = "id: drift\n"
        result = self.module.execute("provision")
        self.assertEqual(result["firstPass"]["mutationCount"], 2)
        self.assertEqual(
            result["firstPass"]["mutations"],
            [
                {
                    "resource": "flow",
                    "action": "updated",
                    "ref": "micro_task_engine.prototype/paperclip-runtime",
                },
                {
                    "resource": "kv",
                    "action": "updated",
                    "ref": "mte.platform/mte.flow.catalog",
                },
            ],
        )
        self.assertEqual(result["secondPass"]["mutationCount"], 0)

    def test_verify_rejects_remote_drift_without_mutation(self):
        self.module.execute("provision")
        identity = ("system.health", "platform-canary")
        revision = self.fake.flows[identity]["revision"]
        self.fake.flows[identity]["source"] = "id: drift\n"
        with self.assertRaisesRegex(
            self.module.ReconcileError, "kestra_flow_requires_reconcile"
        ):
            self.module.execute("verify")
        self.assertEqual(self.fake.flows[identity]["revision"], revision)

    def test_second_pass_requires_stable_remote_timestamps(self):
        self.module.execute("provision")
        self.fake.unstable_reads = True
        with self.assertRaisesRegex(
            self.module.ReconcileError, "kestra_second_reconcile_not_noop"
        ):
            self.module.execute("provision")

    def test_verify_rejects_stale_provision_subject_after_canonical_change(self):
        self.module.execute("provision")
        self.canonical.write_text(
            self.canonical.read_text().replace(
                "unit-only-kestra-secret", "rotated-unit-only-secret"
            )
        )
        self.canonical.chmod(0o600)
        with self.assertRaisesRegex(
            self.module.ReconcileError, "kestra_provision_evidence_binding_invalid"
        ):
            self.module.execute("verify")

    def test_verify_rejects_provision_subject_after_flow_source_change(self):
        self.module.execute("provision")
        path = self.root / "workflows/kestra/platform-canary.yaml"
        path.write_text(path.read_text() + "description: changed\n")
        with self.assertRaisesRegex(
            self.module.ReconcileError, "kestra_provision_evidence_binding_invalid"
        ):
            self.module.execute("verify")

    def test_flow_source_set_is_exact_and_rejects_unmanaged_yaml(self):
        extra = self.root / "workflows/kestra/unmanaged.yaml"
        extra.write_text(
            "id: unmanaged\nnamespace: mte.platform\n"
            "tasks:\n  - id: log\n    type: io.kestra.plugin.core.log.Log\n"
            "    message: no\n"
        )
        with self.assertRaisesRegex(
            self.module.ReconcileError, "kestra_flow_source_set_mismatch"
        ):
            self.module.load_flows()

    def test_profile_runtime_must_be_exact_rendered_three_profile_catalog(self):
        runtime = self.root / "runtime/profiles/profiles.yaml"
        payload = yaml.safe_load(runtime.read_text())
        payload["profiles"][0]["nativeAdapter"] = "${UNRENDERED:?required}"
        payload["profiles"][0]["runtimeContract"]["adapterType"] = (
            "${UNRENDERED:?required}"
        )
        runtime.write_text(yaml.safe_dump(payload, sort_keys=False))
        with self.assertRaisesRegex(
            self.module.ReconcileError, "profile_catalog_runtime_not_rendered"
        ):
            self.module.load_profile_contract()

    def test_evidence_writer_rejects_raw_secret(self):
        with self.assertRaisesRegex(
            self.module.ReconcileError, "kestra_evidence_contains_secret"
        ):
            self.module._atomic_evidence(
                self.verify_evidence,
                {"raw": "unit-only-kestra-secret"},
                self.module.dotenv(),
            )

    def test_evidence_writer_ignores_non_secret_auth_literals(self):
        path = self.root / "evidence/non-secret-literal.json"
        self.module._atomic_evidence(
            path,
            {"enabled": False, "status": "disabled"},
            {
                "SOME_AUTH_ENABLED": "false",
                "SOME_TOKEN_REQUIRED": "required",
            },
        )
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_canonical_connection_values_are_required_before_remote_mutation(self):
        original = self.canonical.read_text()
        required = (
            "KESTRA_ADMIN_USER",
            "KESTRA_ADMIN_PASSWORD",
            "KESTRA_LOOPBACK_HOST",
            "KESTRA_ORIGIN_PORT",
            "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS",
        )
        for key in required:
            with self.subTest(key=key):
                self.canonical.write_text(
                    "\n".join(
                        line
                        for line in original.splitlines()
                        if not line.startswith(f"{key}=")
                    )
                    + "\n"
                )
                self.canonical.chmod(0o600)
                self.fake.calls.clear()
                with self.assertRaisesRegex(
                    self.module.ReconcileError,
                    f"canonical_env_ref_missing:{key}",
                ):
                    self.module.execute("provision")
                self.assertEqual(self.fake.calls, [])
                self.canonical.write_text(original)
                self.canonical.chmod(0o600)

    def test_invalid_canonical_connection_values_fail_before_remote_mutation(self):
        invalid = {
            "KESTRA_LOOPBACK_HOST": (
                "kestra.internal",
                "kestra_origin_not_loopback",
            ),
            "KESTRA_ORIGIN_PORT": ("0", "kestra_origin_port_invalid"),
            "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS": (
                "0",
                "kestra_reconcile_http_timeout_invalid",
            ),
        }
        original = self.canonical.read_text()
        for key, (replacement, error) in invalid.items():
            with self.subTest(key=key):
                self.canonical.write_text(
                    re.sub(
                        rf"(?m)^{re.escape(key)}=.*$",
                        f"{key}={replacement}",
                        original,
                    )
                )
                self.canonical.chmod(0o600)
                self.fake.calls.clear()
                with self.assertRaisesRegex(self.module.ReconcileError, error):
                    self.module.execute("provision")
                self.assertEqual(self.fake.calls, [])
                self.canonical.write_text(original)
                self.canonical.chmod(0o600)

    def test_canonical_endpoint_and_timeout_mutations_drive_every_request(self):
        self.canonical.write_text(
            self.canonical.read_text()
            .replace("KESTRA_LOOPBACK_HOST=127.0.0.1", "KESTRA_LOOPBACK_HOST=localhost")
            .replace("KESTRA_ORIGIN_PORT=18082", "KESTRA_ORIGIN_PORT=28082")
            .replace(
                "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS=60",
                "KESTRA_RECONCILE_HTTP_TIMEOUT_SECONDS=17",
            )
        )
        self.canonical.chmod(0o600)

        result = self.module.execute("provision")

        self.assertEqual(result["firstPass"]["mutationCount"], 6)
        self.assertTrue(self.fake.calls)
        self.assertTrue(
            all(
                call["base"] == "http://localhost:28082"
                and call["timeoutSeconds"] == 17
                for call in self.fake.calls
            )
        )

    def test_ipv6_loopback_is_rendered_as_a_valid_authority(self):
        values = self.module.dotenv()
        values["KESTRA_LOOPBACK_HOST"] = "::1"

        base, _headers, timeout_seconds = self.module.basic_auth(values)

        self.assertEqual(base, "http://[::1]:18082")
        self.assertEqual(timeout_seconds, 60)

    def test_request_passes_the_canonical_timeout_to_urlopen(self):
        module = load_module()
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b"{}"
        with mock.patch.object(
            module.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            status, payload = module.request(
                "http://127.0.0.1:18082",
                {"Authorization": "Basic unit-only"},
                "GET",
                "/api/v1/main/flows",
                timeout_seconds=17,
            )

        self.assertEqual((status, payload), (200, {}))
        urlopen.assert_called_once()
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 17)


if __name__ == "__main__":
    unittest.main()
