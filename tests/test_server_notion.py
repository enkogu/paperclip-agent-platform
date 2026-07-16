import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOT = "11111111-1111-4111-8111-111111111111"
WORKSPACE = "22222222-2222-4222-8222-222222222222"
ROOT_PAGE = "33333333-3333-4333-8333-333333333333"
DOCUMENTS_PAGE = "44444444-4444-4444-8444-444444444444"
DATABASE = "55555555-5555-4555-8555-555555555555"
DATA_SOURCE = "66666666-6666-4666-8666-666666666666"
TABLE_PAGE = "77777777-7777-4777-8777-777777777777"
DOCUMENT_PAGE = "88888888-8888-4888-8888-888888888888"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_notion", ROOT / "tools/platform-cli/server-notion.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def env(module, *, complete=True):
    result = {
        "NOTION_TOKEN": "unit-secret-notion-token",
        "NOTION_API_BASE_URL": module.OFFICIAL_NOTION_BASE_URL,
        "NOTION_API_VERSION": module.NOTION_API_VERSION,
        "NOTION_ROOT_PAGE_ID": ROOT_PAGE,
        "NOTION_WORKSPACE_ID": WORKSPACE,
        "NOTION_BOT_ID": BOT,
    }
    if complete:
        result.update(
            {
                "NOTION_DOCUMENTS_PAGE_ID": DOCUMENTS_PAGE,
                "NOTION_TABLE_DATABASE_ID": DATABASE,
                "NOTION_TABLE_DATA_SOURCE_ID": DATA_SOURCE,
            }
        )
    return result


def text(module, value):
    return [
        {
            "type": "text",
            "text": {"content": value},
            "plain_text": value,
        }
    ]


class FakeNotion:
    def __init__(self, module, *, provisioned=True):
        self.module = module
        self.documents = provisioned
        self.database = provisioned
        self.schema = provisioned
        self.table_page = None
        self.document_page = None
        self.document_children = []
        self.calls = []
        self.created = {"documents": 0, "database": 0, "table": 0, "document": 0}

    def page(self, page_id, title, parent=None, *, archived=False, properties=None):
        page_properties = properties or {
            "title": {"type": "title", "title": text(self.module, title)}
        }
        parent_payload = (
            {"type": "workspace", "workspace": True}
            if parent is None
            else {"type": "page_id", "page_id": parent}
        )
        return {
            "object": "page",
            "id": page_id,
            "parent": parent_payload,
            "archived": archived,
            "properties": page_properties,
        }

    def database_payload(self):
        return {
            "object": "database",
            "id": DATABASE,
            "parent": {"type": "page_id", "page_id": ROOT_PAGE},
            "archived": False,
            "title": text(self.module, self.module.DATABASE_TITLE),
            "data_sources": (
                [{"id": DATA_SOURCE, "name": self.module.DATABASE_TITLE}]
                if self.database
                else []
            ),
        }

    def source_payload(self):
        definitions = (
            self.module.EXPECTED_PROPERTIES if self.schema else {"Name": {"title": {}}}
        )
        properties = {}
        for name, definition in definitions.items():
            kind = next(iter(definition))
            value = {"id": "prop-" + name, "name": name, "type": kind, kind: {}}
            if kind == "select":
                value[kind] = {
                    "options": [
                        {"id": "option-" + option["name"], **option}
                        for option in definition[kind]["options"]
                    ]
                }
            properties[name] = value
        return {
            "object": "data_source",
            "id": DATA_SOURCE,
            "parent": {"type": "database_id", "database_id": DATABASE},
            "title": text(self.module, self.module.DATABASE_TITLE),
            "properties": properties,
        }

    def _plain(self, values):
        return self.module.plain_text(values)

    def __call__(
        self,
        _config,
        method,
        path,
        *,
        body=None,
        expected={200},
        retry_safe=False,
    ):
        del expected, retry_safe
        self.calls.append((method, path, body))
        if method == "GET" and path == "/users/me":
            return 200, {
                "object": "user",
                "id": BOT,
                "type": "bot",
                "bot": {
                    "owner": {"type": "workspace", "workspace": True},
                    "workspace_id": WORKSPACE,
                    "workspace_name": "Unit workspace",
                },
            }
        if method == "GET" and path == "/pages/" + ROOT_PAGE:
            return 200, self.page(ROOT_PAGE, self.module.ROOT_TITLE)
        if method == "GET" and path == "/pages/" + DOCUMENTS_PAGE:
            return 200, self.page(
                DOCUMENTS_PAGE, self.module.DOCUMENTS_TITLE, ROOT_PAGE
            )
        if method == "GET" and path == "/databases/" + DATABASE:
            return 200, self.database_payload()
        if method == "GET" and path == "/data_sources/" + DATA_SOURCE:
            return 200, self.source_payload()
        if method == "POST" and path == "/search":
            results = (
                [self.page(DOCUMENTS_PAGE, self.module.DOCUMENTS_TITLE, ROOT_PAGE)]
                if self.documents
                else []
            )
            return 200, {"results": results, "has_more": False, "next_cursor": None}
        if method == "GET" and path.startswith("/blocks/" + ROOT_PAGE + "/children?"):
            results = (
                [{"object": "block", "id": DATABASE, "type": "child_database"}]
                if self.database
                else []
            )
            return 200, {"results": results, "has_more": False, "next_cursor": None}
        if method == "POST" and path == "/pages":
            parent = body["parent"]
            if parent["type"] == "page_id" and parent["page_id"] == ROOT_PAGE:
                self.documents = True
                self.created["documents"] += 1
                return 200, self.page(
                    DOCUMENTS_PAGE, self.module.DOCUMENTS_TITLE, ROOT_PAGE
                )
            if parent["type"] == "data_source_id":
                self.created["table"] += 1
                self.table_page = self.page(
                    TABLE_PAGE,
                    "",
                    properties=body["properties"],
                )
                self.table_page["parent"] = {
                    "type": "data_source_id",
                    "data_source_id": DATA_SOURCE,
                }
                return 200, self.table_page
            if parent["type"] == "page_id" and parent["page_id"] == DOCUMENTS_PAGE:
                self.created["document"] += 1
                self.document_children = body.get("children", [])
                title = self._plain(body["properties"]["title"]["title"])
                self.document_page = self.page(DOCUMENT_PAGE, title, DOCUMENTS_PAGE)
                return 200, self.document_page
        if method == "POST" and path == "/databases":
            self.database = True
            self.created["database"] += 1
            return 200, self.database_payload()
        if method == "PATCH" and path == "/data_sources/" + DATA_SOURCE:
            self.schema = True
            return 200, self.source_payload()
        if method == "POST" and path == "/data_sources/" + DATA_SOURCE + "/query":
            results = []
            if self.table_page is not None and not self.table_page["archived"]:
                expected_id = body["filter"]["rich_text"]["equals"]
                actual_id = self._plain(
                    self.table_page["properties"]["Postgres Object ID"]["rich_text"]
                )
                if actual_id == expected_id:
                    results = [self.table_page]
            return 200, {"results": results, "has_more": False, "next_cursor": None}
        if method == "PATCH" and path == "/pages/" + TABLE_PAGE:
            if "properties" in body:
                self.table_page["properties"] = body["properties"]
            if body.get("archived") is True:
                self.table_page["archived"] = True
            return 200, self.table_page
        if method == "GET" and path == "/pages/" + TABLE_PAGE:
            return 200, self.table_page
        if method == "PATCH" and path == "/blocks/" + DOCUMENT_PAGE + "/children":
            self.document_children.extend(body["children"])
            return 200, {"object": "list", "results": body["children"]}
        if method == "GET" and path.startswith(
            "/blocks/" + DOCUMENT_PAGE + "/children?"
        ):
            return 200, {
                "results": self.document_children,
                "has_more": False,
                "next_cursor": None,
            }
        if method == "PATCH" and path == "/pages/" + DOCUMENT_PAGE:
            if body.get("archived") is True:
                self.document_page["archived"] = True
            return 200, self.document_page
        if method == "GET" and path == "/pages/" + DOCUMENT_PAGE:
            return 200, self.document_page
        raise AssertionError((method, path, body))


class NotionConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_config_requires_exact_version_root_and_token(self):
        for missing in (
            "NOTION_TOKEN",
            "NOTION_API_BASE_URL",
            "NOTION_API_VERSION",
            "NOTION_ROOT_PAGE_ID",
        ):
            current = env(self.module)
            current.pop(missing)
            with (
                self.subTest(missing=missing),
                self.assertRaises(self.module.NotionError),
            ):
                self.module.config_from_env(current)
        current = env(self.module)
        current["NOTION_API_VERSION"] = "2022-06-28"
        with self.assertRaisesRegex(self.module.NotionError, "version_drift"):
            self.module.config_from_env(current)

    def test_config_repr_and_source_hash_never_contain_token(self):
        config = self.module.config_from_env(env(self.module))
        self.assertNotIn(config.token, repr(config))
        inspected = {"root": {"pageId": ROOT_PAGE}}
        self.assertNotIn(
            config.token, self.module.connector_config_sha(config, inspected)
        )

    def test_cli_config_reads_only_secure_canonical_env(self):
        values = env(self.module)
        with tempfile.TemporaryDirectory() as temporary:
            canonical = Path(temporary) / "platform.env"
            canonical.write_text(
                "".join(f"{key}={value}\n" for key, value in values.items())
            )
            canonical.chmod(0o600)
            with mock.patch.object(self.module, "CANONICAL", canonical):
                config = self.module.config_from_env()
                self.assertEqual(config.root_page_id, ROOT_PAGE)
                canonical.chmod(0o644)
                with self.assertRaisesRegex(
                    self.module.NotionError, "canonical_env_mode_invalid"
                ):
                    self.module.config_from_env()

    def test_http_contract_uses_only_official_base_version_and_bearer(self):
        config = self.module.config_from_env(env(self.module))

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"object":"user"}'

        with mock.patch.object(
            self.module.urllib.request, "urlopen", return_value=Response()
        ) as opened:
            _, payload = self.module.request_json(config, "GET", "/users/me")
        request = opened.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(request.full_url, "https://api.notion.com/v1/users/me")
        self.assertEqual(headers["authorization"], "Bearer " + config.token)
        self.assertEqual(headers["notion-version"], self.module.NOTION_API_VERSION)
        self.assertEqual(payload, {"object": "user"})

    def test_http_failure_never_surfaces_response_or_token(self):
        config = self.module.config_from_env(env(self.module))
        error = urllib.error.HTTPError(
            "https://api.notion.com/v1/users/me",
            401,
            "denied",
            {},
            io.BytesIO(("raw " + config.token).encode()),
        )
        with (
            mock.patch.object(self.module.urllib.request, "urlopen", side_effect=error),
            self.assertRaises(self.module.NotionError) as raised,
        ):
            self.module.request_json(config, "GET", "/users/me")
        error.close()
        self.assertEqual(raised.exception.code, "notion_http_status:401")
        self.assertNotIn(config.token, str(raised.exception))


class NotionProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_existing_resources_are_an_exact_noop(self):
        fake = FakeNotion(self.module)
        config = self.module.config_from_env(env(self.module))
        with (
            mock.patch.object(self.module, "request_json", side_effect=fake),
            mock.patch.object(
                self.module, "canonical_source_sha", return_value="c" * 64
            ),
        ):
            result = self.module.provision(config)
        self.assertEqual(result["status"], "converged")
        self.assertEqual(result["changedKeys"], [])
        self.assertEqual(
            result["created"],
            {
                "documentsPage": False,
                "database": False,
                "dataSource": False,
            },
        )
        self.assertTrue(result["schema"]["exact"])
        self.assertNotIn(config.token, json.dumps(result))

    def test_missing_children_are_created_then_discovered_idempotently(self):
        fake = FakeNotion(self.module, provisioned=False)
        config = self.module.config_from_env(env(self.module, complete=False))
        with (
            mock.patch.object(self.module, "request_json", side_effect=fake),
            mock.patch.object(
                self.module, "canonical_source_sha", return_value="c" * 64
            ),
        ):
            first = self.module.provision(config)
            second = self.module.provision(config)
        self.assertEqual(fake.created["documents"], 1)
        self.assertEqual(fake.created["database"], 1)
        self.assertEqual(first["environmentUpdates"], second["environmentUpdates"])
        self.assertEqual(
            first["changedKeys"],
            [
                "NOTION_DOCUMENTS_PAGE_ID",
                "NOTION_TABLE_DATABASE_ID",
                "NOTION_TABLE_DATA_SOURCE_ID",
            ],
        )
        self.assertTrue(first["schema"]["changed"])
        self.assertFalse(second["schema"]["changed"])

    def test_clean_install_captures_bot_and_workspace_ids_fill_only(self):
        fake = FakeNotion(self.module, provisioned=False)
        values = env(self.module, complete=False)
        values.pop("NOTION_WORKSPACE_ID")
        values.pop("NOTION_BOT_ID")
        config = self.module.config_from_env(values)
        with (
            mock.patch.object(self.module, "request_json", side_effect=fake),
            mock.patch.object(
                self.module, "canonical_source_sha", return_value="c" * 64
            ),
        ):
            result = self.module.provision(config)
        self.assertEqual(result["environmentUpdates"]["NOTION_WORKSPACE_ID"], WORKSPACE)
        self.assertEqual(result["environmentUpdates"]["NOTION_BOT_ID"], BOT)
        self.assertEqual(
            result["changedKeys"],
            [
                "NOTION_BOT_ID",
                "NOTION_DOCUMENTS_PAGE_ID",
                "NOTION_TABLE_DATABASE_ID",
                "NOTION_TABLE_DATA_SOURCE_ID",
                "NOTION_WORKSPACE_ID",
            ],
        )

    def test_root_is_never_created_or_replaced(self):
        fake = FakeNotion(self.module)

        def drifted(config, method, path, **kwargs):
            if method == "GET" and path == "/pages/" + ROOT_PAGE:
                return 200, fake.page(ROOT_PAGE, "Wrong root")
            return fake(config, method, path, **kwargs)

        config = self.module.config_from_env(env(self.module))
        with (
            mock.patch.object(self.module, "request_json", side_effect=drifted),
            self.assertRaisesRegex(self.module.NotionError, "title_drift"),
        ):
            self.module.provision(config)
        self.assertFalse(
            any(method == "POST" and path == "/pages" for method, path, _ in fake.calls)
        )


class NotionCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_real_contract_covers_table_document_cleanup_and_redaction(self):
        fake = FakeNotion(self.module)
        config = self.module.config_from_env(env(self.module))
        run_id = "unit-run-001"
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "notion-connector-verify.json"
            with (
                mock.patch.object(self.module, "request_json", side_effect=fake),
                mock.patch.object(self.module, "EVIDENCE", evidence),
                mock.patch.object(
                    self.module, "CANONICAL", Path(temporary) / "platform.env"
                ),
            ):
                self.module.CANONICAL.write_bytes(b"NOTION_TOKEN=unit\n")
                result = self.module.canary_action(config, run_id)
            persisted = json.loads(evidence.read_text())
            evidence_mode = evidence.stat().st_mode & 0o777
        self.assertEqual(result["kind"], "NotionConnectorCanary")
        self.assertEqual(
            result["canonicalSourceSha256"],
            self.module.hashlib.sha256(b"NOTION_TOKEN=unit\n").hexdigest(),
        )
        self.assertEqual(result["dataContentProfile"], "postgres-notion")
        self.assertTrue(result["notion"]["table"]["queryVerified"])
        self.assertTrue(result["notion"]["table"]["updated"])
        self.assertTrue(result["notion"]["table"]["archived"])
        self.assertTrue(result["notion"]["document"]["appendVerified"])
        self.assertTrue(result["notion"]["document"]["readBackVerified"])
        self.assertTrue(result["notion"]["document"]["archived"])
        self.assertTrue(result["cleanup"]["verified"])
        self.assertEqual(persisted["kind"], "NotionConnectorVerification")
        self.assertEqual(persisted["evidence"]["mode"], "0600")
        self.assertEqual(evidence_mode, 0o600)
        serialized = json.dumps(persisted, sort_keys=True)
        self.assertNotIn(config.token, serialized)
        self.assertNotIn(run_id, serialized)
        for raw in (
            *self.module.linkage_values(run_id, "record"),
            *self.module.linkage_values(run_id, "document"),
        ):
            self.assertNotIn(raw, serialized)

    def test_identity_mismatch_fails_before_any_canary_write(self):
        fake = FakeNotion(self.module)
        current = env(self.module)
        current["NOTION_WORKSPACE_ID"] = "99999999-9999-4999-8999-999999999999"
        config = self.module.config_from_env(current)
        with (
            mock.patch.object(self.module, "request_json", side_effect=fake),
            self.assertRaisesRegex(self.module.NotionError, "workspace_identity_drift"),
        ):
            self.module.inspect_resources(config)
        self.assertEqual(fake.created["table"], 0)
        self.assertEqual(fake.created["document"], 0)

    def test_schema_must_be_exact_before_canary(self):
        fake = FakeNotion(self.module)
        fake.schema = False
        config = self.module.config_from_env(env(self.module))
        with (
            mock.patch.object(self.module, "request_json", side_effect=fake),
            self.assertRaisesRegex(self.module.NotionError, "schema_not_exact"),
        ):
            self.module.inspect_resources(config)

    def test_run_id_is_strictly_validated(self):
        config = self.module.config_from_env(env(self.module))
        with self.assertRaisesRegex(self.module.NotionError, "invalid_run_id"):
            self.module.run_canary(
                config,
                "bad run id",
                {
                    "canonicalSourceSha256": "a" * 64,
                    "identity": {},
                    "resources": {},
                },
            )


if __name__ == "__main__":
    unittest.main()
