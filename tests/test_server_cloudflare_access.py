from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "tools/platform-cli/server-cloudflare-access.py"
    spec = importlib.util.spec_from_file_location("server_cloudflare_access", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CloudflareAccessReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.human_policy = "00000000-0000-0000-0000-000000000011"
        self.service_policy = "00000000-0000-0000-0000-000000000012"
        self.service_policies = {"postgrest": self.service_policy}
        self.tfvars = {
            "account_id": "a" * 32,
            "human_session_duration": "24h",
            "apps": {
                "paperclip": {
                    "hostname": "paperclip.prin7r.example",
                    "origin": "http://127.0.0.1:3100",
                    "access_class": "human",
                },
                "postgrest": {
                    "hostname": "data-api.prin7r.example",
                    "origin": "http://127.0.0.1:18093",
                    "access_class": "service",
                },
            },
        }

    def application(self, app_id: str, payload: dict, **overrides):
        return {"id": app_id, **payload, **overrides}

    def test_plan_updates_one_exact_identity_and_removes_its_duplicate(self) -> None:
        contract = self.module.desired_contract(
            self.tfvars, self.human_policy, self.service_policies
        )
        payload = contract["apps"]["paperclip"]["payload"]
        stale = self.application(
            "00000000-0000-0000-0000-000000000021",
            payload,
            same_site_cookie_attribute="lax",
        )
        duplicate = self.application("00000000-0000-0000-0000-000000000022", payload)
        plan = self.module.access_plan([duplicate, stale], contract)
        self.assertEqual(len(plan["creates"]), 1)
        self.assertEqual(plan["updates"][0][0], stale["id"])
        self.assertEqual(plan["deletes"], [duplicate["id"]])

    def test_apply_is_idempotent_and_does_not_emit_the_token(self) -> None:
        module = self.module
        initial = [
            self.application(
                "00000000-0000-0000-0000-000000000031",
                {
                    "name": "MTE paperclip",
                    "domain": "paperclip.prin7r.example",
                    "type": "self_hosted",
                    "destinations": [
                        {"type": "public", "uri": "paperclip.prin7r.example"}
                    ],
                    "app_launcher_visible": True,
                    "enable_binding_cookie": True,
                    "http_only_cookie_attribute": True,
                    "same_site_cookie_attribute": "lax",
                    "session_duration": "24h",
                    "service_auth_401_redirect": False,
                    "policies": [{"id": self.human_policy, "precedence": 1}],
                },
            )
        ]

        class FakeApi:
            rows = copy.deepcopy(initial)
            creates = []
            updates = []
            deletes = []

            def __init__(self, token):
                if token != "test-token-never-printed":
                    raise AssertionError("wrong token")

            def applications(self, account_id):
                if account_id != "a" * 32:
                    raise AssertionError("wrong account")
                return copy.deepcopy(self.rows)

            def create(self, account_id, payload):
                self.creates.append(copy.deepcopy(payload))
                self.rows.append(
                    {
                        "id": f"00000000-0000-0000-0000-00000000004{len(self.creates)}",
                        **payload,
                    }
                )

            def update(self, account_id, app_id, payload):
                self.updates.append((app_id, copy.deepcopy(payload)))
                self.rows = [
                    {"id": app_id, **payload} if row["id"] == app_id else row
                    for row in self.rows
                ]

            def delete(self, account_id, app_id):
                self.deletes.append(app_id)
                self.rows = [row for row in self.rows if row["id"] != app_id]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / "platform.env"
            tfvars = root / "terraform.tfvars.json"
            evidence = root / "evidence.json"
            env.write_text("CLOUDFLARE_API_TOKEN=test-token-never-printed\n")
            tfvars.write_text(json.dumps(self.tfvars))
            env.chmod(0o600)
            tfvars.chmod(0o600)
            payload = module.reconcile(
                "apply",
                env,
                tfvars,
                self.human_policy,
                self.service_policies,
                evidence,
                api_class=FakeApi,
            )

        self.assertEqual(len(FakeApi.creates), 1)
        self.assertEqual(len(FakeApi.updates), 1)
        self.assertEqual(FakeApi.deletes, [])
        self.assertTrue(payload["reconciledExactly"])
        self.assertNotIn("test-token-never-printed", json.dumps(payload))

    def test_verify_fails_closed_when_a_desired_application_is_missing(self) -> None:
        contract = self.module.desired_contract(
            self.tfvars, self.human_policy, self.service_policies
        )
        with self.assertRaises(self.module.AccessReconcileError) as raised:
            self.module.verify_inventory([], contract)
        self.assertEqual(raised.exception.code, "cloudflare_access_postcondition_drift")

    def test_service_default_session_duration_does_not_cause_drift(self) -> None:
        contract = self.module.desired_contract(
            self.tfvars, self.human_policy, self.service_policies
        )
        payload = contract["apps"]["postgrest"]["payload"]
        observed = self.application(
            "00000000-0000-0000-0000-000000000051",
            {**payload, "session_duration": "24h"},
        )
        self.module.verify_inventory(
            [observed], {"apps": {"postgrest": contract["apps"]["postgrest"]}}
        )

    def test_policy_map_must_exactly_match_service_routes(self) -> None:
        with self.assertRaises(self.module.AccessReconcileError) as raised:
            self.module.desired_contract(self.tfvars, self.human_policy, {})
        self.assertEqual(
            raised.exception.code, "cloudflare_access_policy_binding_missing"
        )

    def test_all_human_and_all_service_contracts_do_not_index_absent_policy(
        self,
    ) -> None:
        human = copy.deepcopy(self.tfvars)
        human["apps"].pop("postgrest")
        self.module.desired_contract(human, self.human_policy, {})
        service = copy.deepcopy(self.tfvars)
        service["apps"].pop("paperclip")
        self.module.desired_contract(service, None, self.service_policies)

    def test_terraform_uses_per_route_maps_and_safe_optional_human_output(self) -> None:
        main = (ROOT / "deployment/cloudflare/main.tf").read_text()
        outputs = (ROOT / "deployment/cloudflare/outputs.tf").read_text()
        self.assertIn("for_each = local.service_apps", main)
        self.assertIn(
            "cloudflare_zero_trust_access_service_token.service[each.key].id", main
        )
        self.assertNotIn("service[0]", main + outputs)
        self.assertIn(
            "try(cloudflare_zero_trust_access_policy.human[0].id, null)", outputs
        )
        self.assertIn('output "service_tokens"', outputs)
        self.assertIn('output "service_access_policy_ids"', outputs)


if __name__ == "__main__":
    unittest.main()
