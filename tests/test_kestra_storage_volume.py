from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_kestra_storage_is_owned_before_runtime_starts():
    document = yaml.safe_load(
        (ROOT / "deployment/services/kestra/compose.yaml").read_text()
    )
    services = document["services"]
    init = services["kestra-storage-init"]
    kestra = services["kestra"]

    assert init["image"] == "${MTE_KESTRA_KESTRA_IMAGE:?required}"
    assert str(init["user"]) == "0:0"
    assert init["network_mode"] == "none"
    assert init["entrypoint"] == ["/bin/sh", "-ec"]
    assert init["restart"] == "no"
    assert init["volumes"] == ["kestra-storage:/app/storage"]
    command = init["command"][0]
    assert "mkdir -p /app/storage" in command
    assert "chown -R 1000:1000 /app/storage" in command
    assert "chmod 0750 /app/storage" in command
    assert kestra["depends_on"] == {
        "kestra-storage-init": {"condition": "service_completed_successfully"}
    }
    assert "kestra-storage:/app/storage" in kestra["volumes"]
    assert document["volumes"]["kestra-storage"]["name"] == "mte-kestra-storage"


def test_kestra_runtime_keeps_non_root_identity():
    document = yaml.safe_load(
        (ROOT / "deployment/services/kestra/compose.yaml").read_text()
    )
    assert "user" not in document["services"]["kestra"]
