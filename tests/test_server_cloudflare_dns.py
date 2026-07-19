from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "tools/platform-cli/server-cloudflare-dns.py"
    spec = importlib.util.spec_from_file_location("server_cloudflare_dns", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CloudflareDnsReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.tunnel_id = "00000000-0000-0000-0000-000000000001"
        self.tfvars = {
            "zone_id": "a" * 32,
            "base_domain": "prin7r.example",
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

    def record(self, record_id: str, **values):
        return {
            "id": record_id,
            "name": values.pop("name", "foreign.prin7r.example"),
            "type": values.pop("type", "A"),
            "content": values.pop("content", "192.0.2.10"),
            "ttl": values.pop("ttl", 1),
            "proxied": values.pop("proxied", False),
            "comment": values.pop("comment", ""),
            **values,
        }

    def test_plan_reserves_shipped_names_and_preserves_foreign_records(self) -> None:
        contract = self.module.desired_contract(self.tfvars, self.tunnel_id)
        records = [
            self.record(
                "paperclip-direct",
                name="paperclip.prin7r.example",
                content="144.91.94.91",
            ),
            self.record(
                "data-api-direct",
                name="data-api.prin7r.example",
                content="161.97.99.120",
            ),
            self.record(
                "retired-activepieces",
                name="activepieces.prin7r.example",
                type="CNAME",
                content="old.cfargotunnel.com",
                proxied=True,
                comment="Managed by MTE platform IaC for activepieces",
            ),
            self.record(
                "foreign-chat",
                name="chat.prin7r.example",
                content="77.237.234.208",
            ),
        ]
        plan = self.module.reconcile_plan(records, contract)
        self.assertEqual(
            {row["id"] for row in plan["deletes"]},
            {"paperclip-direct", "data-api-direct", "retired-activepieces"},
        )
        self.assertEqual(
            {row["name"] for row in plan["posts"]},
            {"paperclip.prin7r.example", "data-api.prin7r.example"},
        )
        self.assertTrue(all(row["proxied"] for row in plan["posts"]))
        self.assertTrue(
            all(
                row["content"] == self.tunnel_id + ".cfargotunnel.com"
                for row in plan["posts"]
            )
        )
        self.assertEqual(plan["retiredManagedRecordCount"], 1)
        self.assertEqual(len(plan["foreignFingerprints"]), 1)

    def test_apply_uses_one_batch_and_proves_foreign_set_unchanged(self) -> None:
        module = self.module
        initial = [
            self.record(
                "paperclip-direct",
                name="paperclip.prin7r.example",
                content="144.91.94.91",
            ),
            self.record(
                "data-api-direct",
                name="data-api.prin7r.example",
                content="161.97.99.120",
            ),
            self.record(
                "foreign-chat",
                name="chat.prin7r.example",
                content="77.237.234.208",
            ),
        ]

        class FakeApi:
            records_state = copy.deepcopy(initial)
            batches = []

            def __init__(self, token):
                if token != "test-token-never-printed":
                    raise AssertionError("wrong token")

            def records(self, zone_id):
                if zone_id != "a" * 32:
                    raise AssertionError("wrong zone")
                return copy.deepcopy(self.records_state)

            def batch(self, zone_id, payload):
                if zone_id != "a" * 32:
                    raise AssertionError("wrong zone")
                self.batches.append(copy.deepcopy(payload))
                deleted = {row["id"] for row in payload["deletes"]}
                self.records_state = [
                    row for row in self.records_state if row["id"] not in deleted
                ]
                for index, row in enumerate(payload["posts"]):
                    self.records_state.append({"id": f"created-{index}", **row})

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
                self.tunnel_id,
                evidence,
                api_class=FakeApi,
            )

        self.assertEqual(len(FakeApi.batches), 1)
        self.assertEqual(
            set(FakeApi.batches[0]),
            {"deletes", "posts"},
        )
        self.assertTrue(payload["batchApplied"])
        self.assertTrue(payload["batchDatabaseTransactionAtomic"])
        self.assertFalse(payload["edgePropagationAtomic"])
        self.assertTrue(payload["desiredRecordsExact"])
        self.assertTrue(payload["proxiedDnsOnly"])
        self.assertEqual(payload["originAddressRecordCount"], 0)
        self.assertTrue(payload["foreignRecordsPreserved"])
        self.assertEqual(payload["foreignRecordCount"], 1)
        self.assertNotIn("test-token-never-printed", json.dumps(payload))

    def test_verify_fails_closed_on_direct_origin_record(self) -> None:
        contract = self.module.desired_contract(self.tfvars, self.tunnel_id)
        with self.assertRaises(self.module.DnsReconcileError) as raised:
            self.module.verify_inventory(
                [
                    self.record(
                        "paperclip-direct",
                        name="paperclip.prin7r.example",
                        content="144.91.94.91",
                    )
                ],
                contract,
            )
        self.assertEqual(raised.exception.code, "cloudflare_dns_postcondition_drift")

    def test_release_contract_uses_batch_dns_owner_and_keeps_access_classes(
        self,
    ) -> None:
        main = (ROOT / "deployment/cloudflare/main.tf").read_text()
        outputs = (ROOT / "deployment/cloudflare/outputs.tf").read_text()
        platform = (ROOT / "config/platform.yaml").read_text()
        self.assertNotIn('resource "cloudflare_dns_record" "platform"', main)
        self.assertIn("from = cloudflare_dns_record.platform", main)
        self.assertIn("destroy = false", main)
        self.assertIn("for id, app in var.apps : id => app.hostname", outputs)
        orchestrator = (ROOT / "tools/platform-cli/platform.py").read_text()
        self.assertIn("server-cloudflare-dns.py", orchestrator)
        self.assertIn("server-cloudflare-access.py", orchestrator)
        self.assertIn(
            'cloudflare_edge_command(cfg, iac_root, api_env, "apply")',
            orchestrator,
        )
        self.assertIn(
            'cloudflare_edge_command(cfg, iac_root, api_env, "verify")',
            orchestrator,
        )
        postgrest = platform.split("- id: postgrest", 1)[1].split("\n    - id:", 1)[0]
        self.assertIn("subdomainRef: POSTGREST_SUBDOMAIN", postgrest)
        self.assertIn("originPortRef: POSTGREST_ORIGIN_PORT", postgrest)
        self.assertIn("accessClassRef: POSTGREST_ACCESS_CLASS", postgrest)
        self.assertNotIn("- id: activepieces", platform)

    def test_official_cloudflare_contracts_are_release_bound(self) -> None:
        self.assertEqual(
            self.module.DNS_BATCH_DOC,
            "https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/batch/",
        )
        self.assertIn("routing-to-tunnel", self.module.TUNNEL_DNS_DOC)


if __name__ == "__main__":
    unittest.main()
