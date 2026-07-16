import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-notion-sync.py"


def load_module():
    name = "mte_server_notion_sync_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def values(module):
    return {
        "DATA_CONTENT_PROFILE": "postgres-notion",
        "POSTGREST_DATA_DB_NAME": "mte_agent_data",
        "POSTGRES_ADMIN_USER": "postgres",
        "NOTION_SYNC_BATCH_SIZE": "25",
        "NOTION_SYNC_MAX_ATTEMPTS": "8",
        "NOTION_SYNC_LEASE_SECONDS": "300",
        "NOTION_SYNC_RETRY_BASE_SECONDS": "5",
        "NOTION_SYNC_INTERVAL_SECONDS": "15",
    }


class FakeNotion:
    def __init__(self, module):
        self.module = module
        self.pages = {}
        self.blocks = {}
        self.counter = 0
        for name in (
            "api_id",
            "block_text",
            "canonical_id",
            "page_title",
            "paragraph",
            "property_number",
            "property_select",
            "property_text",
            "table_properties",
            "title_property",
        ):
            setattr(self, name, getattr(module.NOTION, name))

    def _id(self):
        self.counter += 1
        return str(uuid.UUID(int=self.counter))

    @staticmethod
    def _properties(properties):
        result = {}
        for name, value in properties.items():
            item = dict(value)
            if "title" in item:
                item["type"] = "title"
            elif "rich_text" in item:
                item["type"] = "rich_text"
            elif "number" in item:
                item["type"] = "number"
            elif "select" in item:
                item["type"] = "select"
            elif "date" in item:
                item["type"] = "date"
            result[name] = item
        return result

    def request_json(
        self,
        _config,
        method,
        path,
        *,
        body=None,
        expected=None,
        retry_safe=False,
    ):
        del expected, retry_safe
        if method == "POST" and path == "/pages":
            page_id = self._id()
            page = {
                "object": "page",
                "id": page_id,
                "archived": False,
                "parent": dict(body["parent"]),
                "properties": self._properties(body["properties"]),
            }
            self.pages[page_id] = page
            self.blocks[page_id] = []
            return 200, page
        if method == "PATCH" and path.startswith("/pages/"):
            page_id = path.rsplit("/", 1)[1]
            page = self.pages[page_id]
            if "archived" in body:
                page["archived"] = body["archived"]
            if "properties" in body:
                page["properties"].update(self._properties(body["properties"]))
            return 200, page
        if method == "PATCH" and path.startswith("/blocks/"):
            page_id = path.split("/")[2]
            for child in body["children"]:
                block = dict(child)
                block["id"] = self._id()
                self.blocks[page_id].append(block)
            return 200, {"results": self.blocks[page_id]}
        if method == "DELETE" and path.startswith("/blocks/"):
            block_id = path.rsplit("/", 1)[1]
            for rows in self.blocks.values():
                rows[:] = [row for row in rows if row.get("id") != block_id]
            return 200, {"id": block_id, "archived": True}
        raise AssertionError((method, path, body))

    def retrieve_page(self, _config, page_id):
        return self.pages[page_id]

    def paginated(self, config, path, *, body=None):
        del body
        parts = path.split("/")
        parent_id = parts[2]
        if parent_id == config.documents_page_id:
            return [
                {
                    "id": page_id,
                    "type": "child_page",
                    "child_page": {"title": self.page_title(page)},
                }
                for page_id, page in self.pages.items()
                if page["parent"].get("page_id") == parent_id
                and page["archived"] is False
            ]
        return list(self.blocks.get(parent_id, []))

    def query_object(self, _config, data_source_id, object_id):
        return [
            page
            for page in self.pages.values()
            if page["parent"].get("data_source_id") == data_source_id
            and page["archived"] is False
            and self.property_text(page, "Postgres Object ID", "rich_text") == object_id
        ]


class InMemoryConsumer:
    def __init__(self, module, fake_notion, rows):
        self.module = module
        self.fake_notion = fake_notion
        self.rows = rows
        self.mappings = {}
        self.delivered = []
        self.failed = []
        self.consumer = module.Consumer(
            values(module),
            SimpleNamespace(
                data_source_id="11111111-1111-4111-8111-111111111111",
                documents_page_id="22222222-2222-4222-8222-222222222222",
            ),
            module.settings_from_env(values(module)),
            instance_id="unit-consumer",
            psql=lambda *_args: "",
            notion=fake_notion,
        )
        self.consumer.validate_canonical = self.validate_canonical
        self.consumer.renew_lease = lambda _event: None
        self.consumer.finalize_success = self.finalize_success
        self.consumer.finalize_error = self.finalize_error
        self.consumer.finalize_superseded = lambda event: self.delivered.append(
            (event.id, "superseded")
        )

    def validate_canonical(self, event):
        return self.rows.get((event.object_kind, event.canonical_object_id)), False

    def finalize_success(self, event, provider_object_id):
        if provider_object_id:
            self.mappings[(event.object_kind, event.canonical_object_id)] = (
                provider_object_id
            )
        self.delivered.append((event.id, event.operation))

    def finalize_error(self, event, code):
        self.failed.append((event.id, code))


class NotionProjectionConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def event(
        self,
        *,
        row_id,
        kind,
        object_id,
        external,
        operation,
        revision,
        digest,
        provider_id=None,
    ):
        return self.module.Event(
            id=row_id,
            event_id=str(uuid.UUID(int=row_id + 100)),
            object_kind=kind,
            canonical_object_id=object_id,
            external_object_id=external,
            operation=operation,
            canonical_revision=revision,
            canonical_content_hash=digest,
            attempt_count=1,
            provider_object_id=provider_id,
        )

    def test_settings_are_strict_and_only_from_platform_env(self):
        settings = self.module.settings_from_env(values(self.module))
        self.assertEqual(settings.batch_size, 25)
        self.assertEqual(settings.lease_seconds, 300)
        bad = values(self.module)
        bad["NOTION_SYNC_BATCH_SIZE"] = "0"
        with self.assertRaisesRegex(
            self.module.ProjectionError, "invalid_consumer_setting"
        ):
            self.module.settings_from_env(bad)

    def test_claim_is_skip_locked_leased_and_bound_to_current_sync_revision(self):
        payload = {
            "id": 7,
            "event_id": "11111111-1111-4111-8111-111111111111",
            "object_kind": "entity",
            "canonical_object_id": "22222222-2222-4222-8222-222222222222",
            "external_object_id": "record-7",
            "operation": "upsert",
            "canonical_revision": 3,
            "canonical_content_hash": "a" * 64,
            "attempt_count": 2,
            "provider_object_id": None,
        }
        statements = []

        def psql(_values, _database, statement):
            statements.append(statement)
            return json.dumps(payload)

        consumer = self.module.Consumer(
            values(self.module),
            SimpleNamespace(),
            self.module.settings_from_env(values(self.module)),
            instance_id="claim-test",
            psql=psql,
        )
        event = consumer.claim_next()
        self.assertEqual(event.canonical_revision, 3)
        sql = statements[0]
        self.assertIn("FOR UPDATE OF s, o SKIP LOCKED", sql)
        self.assertIn("o.canonical_revision=s.canonical_revision", sql)
        self.assertIn("lease_expires_at", sql)
        self.assertIn("attempt_count < 8", sql)

    def test_error_digest_never_contains_raw_error(self):
        raw = "token=unit-super-secret"
        digest = self.module.stable_error_digest(raw)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotIn("secret", digest)

    def test_canonical_linkage_is_exact_and_newer_revision_is_superseded(self):
        object_id = "55555555-5555-4555-8555-555555555555"
        event = self.event(
            row_id=8,
            kind="entity",
            object_id=object_id,
            external="record-8",
            operation="upsert",
            revision=2,
            digest="d" * 64,
        )
        consumer = self.module.Consumer(
            values(self.module),
            SimpleNamespace(),
            self.module.settings_from_env(values(self.module)),
            instance_id="linkage-test",
            psql=lambda *_args: "",
        )
        exact = {
            "id": object_id,
            "external_object_id": "record-8",
            "revision": 2,
            "content_hash": "d" * 64,
        }
        consumer.canonical_row = lambda _event: exact
        self.assertEqual(consumer.validate_canonical(event), (exact, False))
        consumer.canonical_row = lambda _event: {**exact, "revision": 3}
        self.assertEqual(consumer.validate_canonical(event)[1], True)
        consumer.canonical_row = lambda _event: {**exact, "content_hash": "e" * 64}
        with self.assertRaisesRegex(
            self.module.ProjectionError, "canonical_event_linkage_drift"
        ):
            consumer.validate_canonical(event)

    def test_success_and_failure_transitions_update_both_state_tables(self):
        event = self.event(
            row_id=9,
            kind="document",
            object_id="66666666-6666-4666-8666-666666666666",
            external="doc-9",
            operation="upsert",
            revision=4,
            digest="f" * 64,
        )
        statements = []
        responses = iter(("1|1|0", "1|1|0|0"))

        def psql(_values, _database, statement):
            statements.append(statement)
            return next(responses)

        consumer = self.module.Consumer(
            values(self.module),
            SimpleNamespace(),
            self.module.settings_from_env(values(self.module)),
            instance_id="transition-test",
            psql=psql,
        )
        consumer.finalize_success(event, "77777777-7777-4777-8777-777777777777")
        self.assertFalse(consumer.finalize_error(event, "notion_http_status:503"))
        self.assertIn("UPDATE api.provider_outbox", statements[0])
        self.assertIn("UPDATE api.provider_sync_state", statements[0])
        self.assertIn("sync_status='synced'", statements[0])
        self.assertIn("delivery_state='failed'", statements[1])
        self.assertIn("sync_status='error'", statements[1])
        self.assertNotIn("notion_http_status:503", statements[1])

    def test_expired_processing_at_max_attempts_is_reaped_fail_closed(self):
        statements = []

        def psql(_values, _database, statement):
            statements.append(statement)
            return "2"

        consumer = self.module.Consumer(
            values(self.module),
            SimpleNamespace(),
            self.module.settings_from_env(values(self.module)),
            instance_id="reaper-test",
            psql=psql,
        )
        self.assertEqual(consumer.reap_exhausted(), 2)
        sql = statements[0]
        self.assertIn("delivery_state='processing'", sql)
        self.assertIn("lease_expires_at <= now()", sql)
        self.assertIn("attempt_count >= 8", sql)
        self.assertIn("delivery_state='failed'", sql)
        self.assertIn("sync_status='error'", sql)
        self.assertIn("FOR UPDATE OF o, s SKIP LOCKED", sql)

    def test_systemd_units_are_hardened_and_idempotent(self):
        settings = self.module.settings_from_env(values(self.module))
        service, timer = self.module.unit_documents(settings)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("UMask=0077", service)
        self.assertIn(f"ReadOnlyPaths={self.module.SECRET_ROOT}", service)
        read_write_line = next(
            line for line in service.splitlines() if line.startswith("ReadWritePaths=")
        )
        self.assertNotIn(str(self.module.SECRET_ROOT), read_write_line)
        self.assertEqual(
            read_write_line,
            f"ReadWritePaths={self.module.ROOT / 'evidence'} /run/docker.sock",
        )
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn("OnUnitActiveSec=15s", timer)

    def test_live_canary_identifiers_are_deterministic_and_do_not_expose_run_id(self):
        first = self.module.canary_identifiers("unit-live-canary")
        second = self.module.canary_identifiers("unit-live-canary")
        self.assertEqual(first, second)
        self.assertRegex(first["runHash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("unit-live-canary", json.dumps(first, sort_keys=True))
        self.assertNotEqual(first["entityId"], first["documentId"])
        with self.assertRaisesRegex(
            self.module.ProjectionError, "invalid_projection_canary_run_id"
        ):
            self.module.canary_identifiers("invalid run id")

    def test_live_canary_state_is_bound_to_canonical_sync_and_outbox_rows(self):
        object_id = "88888888-8888-4888-8888-888888888888"
        provider_id = "99999999-9999-4999-8999-999999999999"
        content_hash = "a" * 64
        response = {
            "canonicalExists": True,
            "canonicalRevision": 2,
            "canonicalContentHash": content_hash,
            "sync": {
                "desiredOperation": "upsert",
                "canonicalRevision": 2,
                "canonicalContentHash": content_hash,
                "projectedRevision": 2,
                "projectedContentHash": content_hash,
                "syncStatus": "synced",
                "providerObjectId": provider_id,
                "errorFree": True,
                "leaseReleased": True,
            },
            "outbox": {
                "deliveryState": "delivered",
                "attemptCount": 1,
                "delivered": True,
                "errorFree": True,
                "leaseReleased": True,
            },
        }
        statements = []

        def psql(_values, _database, statement):
            statements.append(statement)
            return json.dumps(response)

        consumer = self.module.Consumer(
            values(self.module),
            SimpleNamespace(),
            self.module.settings_from_env(values(self.module)),
            instance_id="canary-state-test",
            psql=psql,
        )
        evidence, actual_provider_id = self.module.canary_state(
            consumer,
            object_kind="entity",
            canonical_object_id=object_id,
            operation="upsert",
            revision=2,
            content_hash=content_hash,
            canonical_expected=True,
        )
        self.assertEqual(actual_provider_id, provider_id)
        self.assertTrue(all(evidence.values()))
        self.assertIn("api.canonical_entities", statements[0])
        self.assertIn("api.provider_sync_state", statements[0])
        self.assertIn("api.provider_outbox", statements[0])

        response["sync"]["projectedContentHash"] = "b" * 64
        with self.assertRaisesRegex(
            self.module.ProjectionError, "projection_canary_delivery_state_drift"
        ):
            self.module.canary_state(
                consumer,
                object_kind="entity",
                canonical_object_id=object_id,
                operation="upsert",
                revision=2,
                content_hash=content_hash,
                canonical_expected=True,
            )

    def test_live_canary_evidence_rejects_secrets_and_raw_markers(self):
        safe = {"kind": "NotionProjectionLiveCanary", "redacted": True}
        self.module.assert_canary_redacted(
            safe,
            {"NOTION_TOKEN": "unit-secret-token"},
            ["unit-raw-marker"],
        )
        with self.assertRaisesRegex(
            self.module.ProjectionError, "projection_canary_secret_leak"
        ):
            self.module.assert_canary_redacted(
                {**safe, "bad": "unit-secret-token"},
                {"NOTION_TOKEN": "unit-secret-token"},
                ["unit-raw-marker"],
            )
        with self.assertRaisesRegex(
            self.module.ProjectionError, "projection_canary_raw_marker_leak"
        ):
            self.module.assert_canary_redacted(
                {**safe, "bad": "unit-raw-marker"},
                {"NOTION_TOKEN": "unit-secret-token"},
                ["unit-raw-marker"],
            )

    def test_live_canary_cleanup_accepts_pages_already_archived_by_consumer(self):
        fake = FakeNotion(self.module)
        identifiers = self.module.canary_identifiers("cleanup-unit-canary")
        entity_page = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        document_page = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        fake.pages[entity_page] = {
            "id": entity_page,
            "archived": True,
            "parent": {"data_source_id": "unused"},
            "properties": {},
        }
        fake.pages[document_page] = {
            "id": document_page,
            "archived": True,
            "parent": {"page_id": "unused"},
            "properties": {},
        }
        statements = []

        def psql(_values, _database, statement):
            statements.append(statement)
            if "jsonb_build_object" in statement:
                return json.dumps({"canonical": 0, "syncState": 0, "outbox": 0})
            return ""

        consumer = self.module.Consumer(
            values(self.module),
            SimpleNamespace(),
            self.module.settings_from_env(values(self.module)),
            instance_id="canary-cleanup-test",
            psql=psql,
            notion=fake,
        )
        result = self.module.cleanup_canary(
            consumer,
            identifiers,
            {"entity": entity_page, "document": document_page},
        )
        self.assertTrue(all(result.values()))
        self.assertEqual(len(statements), 2)
        self.assertIn("DELETE FROM api.provider_outbox", statements[0])
        self.assertIn("DELETE FROM api.provider_sync_state", statements[0])

    def test_e2e_contract_projects_updates_and_archives_table_and_document(self):
        fake = FakeNotion(self.module)
        entity_id = "33333333-3333-4333-8333-333333333333"
        document_id = "44444444-4444-4444-8444-444444444444"
        entity_hash_1 = "a" * 64
        entity_hash_2 = "b" * 64
        document_hash = "c" * 64
        rows = {
            ("entity", entity_id): {
                "id": entity_id,
                "external_object_id": "customer-1",
                "title": "Customer one",
                "data": {"state": "new"},
                "metadata": {"source": "unit"},
                "revision": 1,
                "content_hash": entity_hash_1,
            },
            ("document", document_id): {
                "id": document_id,
                "external_object_id": "doc-1",
                "title": "Document one",
                "body": "body " * 1000,
                "content_type": "text/markdown",
                "metadata": {"source": "unit"},
                "revision": 1,
                "content_hash": document_hash,
            },
        }
        harness = InMemoryConsumer(self.module, fake, rows)
        entity = self.event(
            row_id=1,
            kind="entity",
            object_id=entity_id,
            external="customer-1",
            operation="upsert",
            revision=1,
            digest=entity_hash_1,
        )
        document = self.event(
            row_id=2,
            kind="document",
            object_id=document_id,
            external="doc-1",
            operation="upsert",
            revision=1,
            digest=document_hash,
        )
        self.assertEqual(harness.consumer.process(entity), "delivered")
        self.assertEqual(harness.consumer.process(document), "delivered")
        self.assertEqual(harness.failed, [])

        entity_page = harness.mappings[("entity", entity_id)]
        document_page = harness.mappings[("document", document_id)]
        rows[("entity", entity_id)] = {
            **rows[("entity", entity_id)],
            "data": {"state": "verified"},
            "revision": 2,
            "content_hash": entity_hash_2,
        }
        entity_update = self.event(
            row_id=3,
            kind="entity",
            object_id=entity_id,
            external="customer-1",
            operation="upsert",
            revision=2,
            digest=entity_hash_2,
            provider_id=entity_page,
        )
        self.assertEqual(harness.consumer.process(entity_update), "delivered")
        metadata, body = harness.consumer.readback_body(entity_page)
        self.assertEqual(metadata["revision"], 2)
        self.assertIn("verified", body)

        rows.pop(("entity", entity_id))
        rows.pop(("document", document_id))
        entity_delete = self.event(
            row_id=4,
            kind="entity",
            object_id=entity_id,
            external="customer-1",
            operation="delete",
            revision=2,
            digest=entity_hash_2,
            provider_id=entity_page,
        )
        document_delete = self.event(
            row_id=5,
            kind="document",
            object_id=document_id,
            external="doc-1",
            operation="delete",
            revision=1,
            digest=document_hash,
            provider_id=document_page,
        )
        self.assertEqual(harness.consumer.process(entity_delete), "delivered")
        self.assertEqual(harness.consumer.process(document_delete), "delivered")
        self.assertTrue(fake.pages[entity_page]["archived"])
        self.assertTrue(fake.pages[document_page]["archived"])
        self.assertEqual(harness.failed, [])

    def test_platform_index_and_schema_register_consumer(self):
        platform_source = (ROOT / "tools/platform-cli/platform.py").read_text()
        postgres_source = (ROOT / "tools/platform-cli/server-postgrest.py").read_text()
        config_source = (ROOT / "tools/platform-cli/server-config.py").read_text()
        self.assertIn('"notion-projection"', platform_source)
        self.assertIn('"server-notion-sync.py"', platform_source)
        self.assertIn("FOR UPDATE OF s, o SKIP LOCKED", SCRIPT.read_text())
        self.assertGreaterEqual(postgres_source.count("lease_expires_at"), 5)
        for key in (
            "NOTION_SYNC_BATCH_SIZE",
            "NOTION_SYNC_MAX_ATTEMPTS",
            "NOTION_SYNC_LEASE_SECONDS",
            "NOTION_SYNC_RETRY_BASE_SECONDS",
            "NOTION_SYNC_INTERVAL_SECONDS",
        ):
            self.assertIn(key, config_source)


if __name__ == "__main__":
    unittest.main()
