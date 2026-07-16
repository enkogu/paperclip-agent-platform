import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "mte_server_wikijs", ROOT / "tools/platform-cli/server-wikijs.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WikiJsTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_compose_is_pinned_private_and_uses_external_postgres(self):
        path = ROOT / "deployment/services/wikijs/compose.yaml"
        raw = path.read_text()
        compose = yaml.safe_load(raw)
        self.assertEqual(compose["name"], "mte-wikijs")
        wiki = compose["services"]["wiki"]
        self.assertEqual(wiki["image"], "${MTE_WIKIJS_WIKI_IMAGE:?required}")
        self.assertEqual(wiki["environment"]["DB_TYPE"], "postgres")
        self.assertEqual(wiki["environment"]["DB_HOST"], "${WIKIJS_DB_HOST:?required}")
        self.assertNotIn("postgres", compose["services"])
        self.assertEqual(wiki["ports"], ["${MTE_WIKIJS_WIKI_PORT_1_MAPPING:?required}"])
        self.assertNotIn("0.0.0.0", raw)
        self.assertTrue(wiki["read_only"])
        self.assertEqual(wiki["cap_drop"], ["ALL"])
        self.assertEqual(compose["networks"]["data-plane"]["name"], "mte-data-plane")
        self.assertTrue(compose["networks"]["data-plane"]["external"])
        self.assertEqual(compose["volumes"]["wikijs-data"]["name"], "mte-wikijs-data")

    def test_final_manifest_is_the_direct_deployment_contract(self):
        path = ROOT / "deployment/services/wikijs/compose.yaml"
        self.assertTrue(path.is_file())
        self.assertEqual(path.parent, ROOT / "deployment/services/wikijs")

    def test_database_creates_isolated_role_and_database_without_argv_secret(self):
        values = {
            "POSTGRES_ADMIN_USER": "postgres_admin",
            "WIKIJS_DB_NAME": "wikijs",
            "WIKIJS_DB_USER": "wikijs",
            "WIKIJS_DB_PASSWORD": "unit-only-db-password",
        }
        sql_calls = []

        def psql(_container, _user, _database, sql):
            sql_calls.append(sql)
            if "FROM pg_roles" in sql:
                return ""
            if "SELECT 1 FROM pg_database" in sql:
                return ""
            if "FROM pg_database d JOIN pg_roles" in sql:
                return "wikijs|wikijs"
            return ""

        completed = mock.Mock(stdout="")
        with (
            mock.patch.object(self.module, "dotenv", return_value=values),
            mock.patch.object(
                self.module, "postgres_container", return_value="postgres-id"
            ),
            mock.patch.object(self.module, "psql", side_effect=psql),
            mock.patch.object(self.module, "run", return_value=completed) as runner,
        ):
            result = self.module.database()
        self.assertTrue(result["database"]["isIsolated"])
        self.assertTrue(result["database"]["ownerMatches"])
        createdb_argv = runner.call_args.args[0]
        self.assertIn("createdb", createdb_argv)
        self.assertNotIn(values["WIKIJS_DB_PASSWORD"], " ".join(createdb_argv))
        self.assertIn(values["WIKIJS_DB_PASSWORD"], "\n".join(sql_calls))
        self.assertIn("REVOKE ALL ON DATABASE", "\n".join(sql_calls))
        self.assertIn(
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC", "\n".join(sql_calls)
        )

    def test_managed_api_key_enables_creates_and_persists_once(self):
        values = {
            "WIKIJS_API_KEY_NAME": "MTE Agent API",
            "WIKIJS_API_KEY_EXPIRATION": "3y",
        }
        created_token = "unit-only-created-api-token-" + "x" * 40
        rows = [
            {
                "id": 17,
                "name": "MTE Agent API",
                "keyShort": "..." + created_token[-20:],
                "isRevoked": False,
            }
        ]
        with (
            mock.patch.object(
                self.module, "api_snapshot", side_effect=[(False, []), (True, rows)]
            ),
            mock.patch.object(self.module, "set_api_state") as enable,
            mock.patch.object(
                self.module, "create_api_key", return_value=created_token
            ) as create,
            mock.patch.object(self.module, "revoke_api_key") as revoke,
            mock.patch.object(
                self.module, "release_contract", return_value={"version": "2.5.314"}
            ),
            mock.patch.object(self.module, "bearer_works", return_value=True),
            mock.patch.object(self.module, "write_canonical_updates") as persist,
        ):
            result = self.module.managed_api_key(
                "http://wikijs", values, "admin-session"
            )
        self.assertEqual(result["mutations"], 2)
        self.assertEqual(result["apiKeyId"], 17)
        self.assertNotIn(created_token, str(result))
        enable.assert_called_once()
        create.assert_called_once()
        revoke.assert_not_called()
        persist.assert_called_once_with(
            {"WIKIJS_API_TOKEN": created_token, "WIKIJS_API_TOKEN_ID": "17"}
        )

    def test_managed_api_key_is_noop_when_canonical_binding_is_exact(self):
        token = "unit-only-existing-api-token-" + "y" * 40
        values = {
            "WIKIJS_API_KEY_NAME": "MTE Agent API",
            "WIKIJS_API_KEY_EXPIRATION": "3y",
            "WIKIJS_API_TOKEN": token,
            "WIKIJS_API_TOKEN_ID": "23",
        }
        rows = [
            {
                "id": 23,
                "name": "MTE Agent API",
                "keyShort": "..." + token[-20:],
                "isRevoked": False,
            }
        ]
        with (
            mock.patch.object(self.module, "api_snapshot", return_value=(True, rows)),
            mock.patch.object(
                self.module, "release_contract", return_value={"version": "2.5.314"}
            ),
            mock.patch.object(self.module, "bearer_works", return_value=True),
            mock.patch.object(self.module, "create_api_key") as create,
            mock.patch.object(self.module, "write_canonical_updates") as persist,
        ):
            result = self.module.managed_api_key(
                "http://wikijs", values, "admin-session"
            )
        self.assertEqual(result["mutations"], 0)
        create.assert_not_called()
        persist.assert_not_called()

    def test_provision_requires_a_real_second_run_noop(self):
        with mock.patch.object(
            self.module,
            "provision_once",
            side_effect=[
                {
                    "mutations": 3,
                    "apiEnabled": True,
                    "apiKeyId": 5,
                    "apiKeyName": "MTE Agent API",
                    "apiTokenFingerprint": "a" * 16,
                },
                {
                    "mutations": 0,
                    "apiEnabled": True,
                    "apiKeyId": 5,
                    "apiKeyName": "MTE Agent API",
                    "apiTokenFingerprint": "a" * 16,
                },
            ],
        ):
            result = self.module.provision()
        self.assertTrue(result["secondRunNoOp"])
        self.assertEqual(result["firstRunMutations"], 3)

    def test_verify_proves_bearer_crud_restart_persistence_and_safe_evidence(self):
        image = (
            "ghcr.io/requarks/wiki:2.5.314@"
            "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e"
        )
        api_token = "unit-only-wikijs-api-token-" + "z" * 48
        db_password = "unit-only-wikijs-db-password"
        values = {
            "MTE_WIKIJS_WIKI_IMAGE": image,
            "WIKIJS_DB_HOST": "mte-postgres",
            "WIKIJS_DB_NAME": "wikijs",
            "WIKIJS_DB_USER": "wikijs",
            "WIKIJS_DB_PASSWORD": db_password,
            "WIKIJS_API_TOKEN": api_token,
            "WIKIJS_API_TOKEN_ID": "31",
            "WIKIJS_API_KEY_NAME": "MTE Agent API",
            "WIKIJS_ORIGIN_PORT": "18086",
        }
        state = {"reads": 0}

        def create(_base, _token, path, content):
            state["path"] = path
            state["content"] = content
            return 41

        def update(_base, _token, page_id, content):
            self.assertEqual(page_id, 41)
            state["updated"] = content

        def read(_base, _token, page_id):
            self.assertEqual(page_id, 41)
            state["reads"] += 1
            if state["reads"] == 3:
                return None
            return {"id": 41, "path": state["path"], "content": state["updated"]}

        before = {
            "id": "container123",
            "name": "mte-wikijs-wiki-1",
            "image": image,
            "restartCount": 0,
            "startedAt": "2026-07-15T01:00:00Z",
        }
        after = {**before, "startedAt": "2026-07-15T01:01:00Z"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "platform.env"
            canonical.write_text(
                "".join(f"{key}={value}\n" for key, value in values.items())
            )
            canonical.chmod(0o600)
            evidence = root / "evidence/wikijs-verify.json"
            with (
                mock.patch.object(self.module, "CANONICAL", canonical),
                mock.patch.object(self.module, "EVIDENCE", evidence),
                mock.patch.object(
                    self.module,
                    "release_contract",
                    return_value={
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "imageRef": image,
                        "version": "2.5.314",
                        "digest": image.rsplit("@", 1)[1],
                    },
                ),
                mock.patch.object(
                    self.module,
                    "provision",
                    return_value={
                        "apiEnabled": True,
                        "apiKeyId": 31,
                        "apiKeyName": "MTE Agent API",
                        "secondRunNoOp": True,
                        "apiTokenFingerprint": self.module.fingerprint(api_token),
                    },
                ),
                mock.patch.object(
                    self.module,
                    "system_info",
                    return_value={
                        "currentVersion": "2.5.314",
                        "dbType": "postgres",
                        "dbHost": "mte-postgres",
                    },
                ),
                mock.patch.object(
                    self.module,
                    "database_state",
                    return_value={
                        "type": "postgres",
                        "name": "wikijs",
                        "user": "wikijs",
                        "owner": "wikijs",
                        "isIsolated": True,
                        "ownerMatches": True,
                    },
                ),
                mock.patch.object(
                    self.module, "wiki_container", return_value="container-id"
                ),
                mock.patch.object(
                    self.module, "container_snapshot", side_effect=[before, after]
                ),
                mock.patch.object(self.module, "create_page", side_effect=create),
                mock.patch.object(self.module, "update_page", side_effect=update),
                mock.patch.object(self.module, "read_page", side_effect=read),
                mock.patch.object(self.module, "delete_page") as delete,
                mock.patch.object(self.module, "http_status", return_value=404),
                mock.patch.object(self.module, "wait_ready"),
                mock.patch.object(
                    self.module, "run", return_value=mock.Mock(stdout="")
                ),
            ):
                result = self.module.verify()
            raw = evidence.read_text()
            stored = json.loads(raw)
            self.assertTrue(result["graphql"]["restartObserved"])
            self.assertTrue(result["graphql"]["persistenceVerified"])
            self.assertTrue(result["graphql"]["cleanupCompleted"])
            self.assertEqual(result["graphql"]["postDeleteStatus404"], 404)
            self.assertEqual(result["graphql"]["beforeRestartPageId"], 41)
            self.assertEqual(result["graphql"]["afterRestartPageId"], 41)
            self.assertEqual(stored["apiVersion"], "micro-task-engine/v1alpha1")
            self.assertEqual(stored["kind"], "WikiJsVerification")
            self.assertEqual(stored["status"], "passed")
            self.assertNotIn(api_token, raw)
            self.assertNotIn(db_password, raw)
            self.assertNotIn(state["path"], raw)
            self.assertNotIn(state["content"], raw)
            self.assertNotIn(state["updated"], raw)
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            delete.assert_called_once_with("http://127.0.0.1:18086", api_token, 41)

    def test_release_evidence_is_exact_and_osi_open_source(self):
        image = (
            "ghcr.io/requarks/wiki:2.5.314@"
            "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e"
        )
        with mock.patch.object(
            self.module, "PLATFORM_LOCK", ROOT / "config/platform.lock.yaml"
        ):
            contract = self.module.release_contract({"MTE_WIKIJS_WIKI_IMAGE": image})
        self.assertEqual(contract["apiVersion"], "micro-task-engine/v1alpha1")
        self.assertEqual(contract["version"], "2.5.314")
        self.assertEqual(
            contract["digest"],
            "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e",
        )
        self.assertEqual(self.module.LICENSE_SPDX, "AGPL-3.0-only")
        self.assertEqual(
            self.module.UPSTREAM_COMMIT,
            "6f042e97cc2d3acda6b6ff611de8e0faacce91c1",
        )


if __name__ == "__main__":
    unittest.main()
