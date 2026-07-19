#!/usr/bin/env python3
"""Render normalized runtime/specialization bundles without credentials.

The catalog remains YAML throughout deployment.  These per-profile bundles are
deliberate JSON interchange artifacts and therefore use an honest ``.json``
suffix.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from profile_catalog import load_profile_catalog


ROOT = Path(__file__).resolve().parents[2]


def render_profile_bundles(catalog_path: Path, output: Path) -> list[str]:
    """Render every declared profile; catalog membership is never hardcoded."""
    catalog = load_profile_catalog(catalog_path)
    output.mkdir(parents=True, exist_ok=True)
    rendered: list[str] = []
    for profile in catalog.profiles:
        target = output / profile["ref"]
        target.mkdir(parents=True, exist_ok=True)
        runtime = profile["runtimeContract"]
        normalized = {
            "id": profile["ref"],
            "runtime": profile.get(
                "runtime",
                {
                    "adapter": runtime["adapterType"],
                    "config": profile["nativeAdapterConfig"],
                },
            ),
            "specialization": profile.get(
                "specialization",
                {
                    "instructions": profile["instructions"],
                    "skills": profile.get("skills", []),
                    "plugins": profile.get("plugins", []),
                    "mcpPolicy": profile.get("mcpPolicy", {}),
                },
            ),
            "extensions": list(catalog.extensions_for(profile["ref"])),
            "limits": profile.get("limits", {}),
            "approval": profile.get("approval", {}),
        }
        path = target / "profile.json"
        path.write_text(json.dumps(normalized, indent=2) + "\n")
        rendered.append(str(path))
    return rendered


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--catalog", type=Path, default=ROOT / "config/profiles/catalog.yaml"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rendered = render_profile_bundles(args.catalog, args.output)
    print(json.dumps({"rendered": rendered}, indent=2))


if __name__ == "__main__":
    main()
