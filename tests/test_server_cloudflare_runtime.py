import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "tools/platform-cli/server-cloudflare-runtime.py"
    spec = importlib.util.spec_from_file_location("server_cloudflare_runtime", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CloudflareRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def runtime_values(self):
        return {
            "CLOUDFLARE_TUNNEL_TOKEN": "t" * 64,
            "CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID": "service-token-id-1234",
            "CLOUDFLARE_ACCESS_CLIENT_ID": "client-id-1234567890",
            "CLOUDFLARE_ACCESS_CLIENT_SECRET": "s" * 48,
            "CLOUDFLARE_ACCESS_EXPIRES_AT": (
                datetime.now(timezone.utc) + timedelta(days=30)
            ).isoformat(timespec="microseconds"),
        }

    def test_runtime_contract_is_secret_free_and_expiry_bound(self):
        values = self.runtime_values()
        result = self.module.runtime_contract(values)
        self.assertTrue(result["ready"])
        self.assertTrue(result["serviceTokenExpiryVerified"])
        encoded = json.dumps(result, sort_keys=True)
        self.assertTrue(all(value not in encoded for value in values.values()))
        values["CLOUDFLARE_ACCESS_EXPIRES_AT"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(self.module.RuntimeErrorSafe):
            self.module.runtime_contract(values)

    def test_reconcile_and_status_never_emit_raw_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "platform.env"
            source.write_text("PLATFORM_BASE_DOMAIN=example.test\n")
            tunnel = base / "tunnel"
            service = base / "service.json"
            values = self.runtime_values()
            tunnel.write_text(values["CLOUDFLARE_TUNNEL_TOKEN"])
            service.write_text(
                json.dumps(
                    {
                        "id": values["CLOUDFLARE_ACCESS_SERVICE_TOKEN_ID"],
                        "client_id": values["CLOUDFLARE_ACCESS_CLIENT_ID"],
                        "client_secret": values["CLOUDFLARE_ACCESS_CLIENT_SECRET"],
                        "expires_at": values["CLOUDFLARE_ACCESS_EXPIRES_AT"],
                    }
                )
            )
            with (
                mock.patch.object(self.module, "SECRET_ROOT", base),
                mock.patch.object(self.module, "SOURCE", source),
                mock.patch.object(self.module, "LOCK", base / ".platform-env.lock"),
                mock.patch.object(self.module, "secure_root_file"),
                mock.patch.object(
                    self.module, "locked", side_effect=lambda: contextlib.nullcontext()
                ),
                mock.patch.object(
                    self.module,
                    "producer_metadata",
                    return_value={
                        "producerPath": "/opt/mte-platform/bin/server-cloudflare-runtime.py",
                        "producerSha256": "a" * 64,
                        "producerOwner": "root:root",
                        "producerMode": "0700",
                    },
                ),
            ):
                reconciled = self.module.reconcile(tunnel, service)
                observed = self.module.status()
            self.assertTrue(reconciled["ready"])
            self.assertTrue(observed["ready"])
            self.assertRegex(reconciled["generatedAt"], r"\.\d{6}\+00:00$")
            encoded = json.dumps([reconciled, observed], sort_keys=True)
            self.assertTrue(all(value not in encoded for value in values.values()))

    def test_secure_root_file_rejects_wrong_owner_mode_and_symlink(self):
        path = mock.Mock()
        path.is_file.return_value = True
        path.is_symlink.return_value = False
        path.stat.return_value = mock.Mock(
            st_uid=0,
            st_gid=0,
            st_mode=stat.S_IFREG | 0o600,
        )
        self.module.secure_root_file(path, 0o600)
        path.stat.return_value.st_uid = 1000
        with self.assertRaises(self.module.RuntimeErrorSafe):
            self.module.secure_root_file(path, 0o600)
        path.stat.return_value.st_uid = 0
        path.is_symlink.return_value = True
        with self.assertRaises(self.module.RuntimeErrorSafe):
            self.module.secure_root_file(path, 0o600)


if __name__ == "__main__":
    unittest.main()
