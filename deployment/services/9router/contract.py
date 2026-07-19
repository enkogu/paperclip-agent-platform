#!/usr/bin/env python3
"""Read-only, secret-safe readiness check for the 9Router runtime contract.

The check intentionally proves only the parts a service-side client can prove:
the health endpoint responds, the three profile-scoped router keys can list
models, and (when explicitly required) Codex and Claude subscription providers
are active. It never creates providers, keys, or OAuth sessions.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import urllib.error
import urllib.request


PROFILE_KEY_REFS = {
    "coding-daytona-codex": "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY",
    "coding-daytona-claude": "NINEROUTER_PROFILE_CODING_DAYTONA_CLAUDE_API_KEY",
    "coding-daytona-pi": "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
}
SUBSCRIPTION_PROVIDERS = ("codex", "claude")
ALLOWED_SUBSCRIPTION_AUTH_TYPES = frozenset({"oauth", "access_token"})


class RouterContractError(RuntimeError):
    """A public, secret-safe condition that prevents a route from being ready."""


def dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RouterContractError(f"invalid_env_line:{number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            raise RouterContractError(f"invalid_env_key:{number}")
        values[key] = value.strip().strip('"').strip("'")
    return values


def normalized_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RouterContractError("invalid_base_url")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def request_json(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
            **(headers or {}),
        },
    )
    path = urlsplit(url).path
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise RouterContractError(f"http_{error.code}:{method}:{path}") from error
    except urllib.error.URLError as error:
        raise RouterContractError(f"request_failed:{method}:{path}") from error
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise RouterContractError(f"invalid_json:{method}:{path}") from error


def provider_connections(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("connections", payload.get("providers", []))
    else:
        rows = []
    if not isinstance(rows, list):
        raise RouterContractError("invalid_provider_list")
    return [row for row in rows if isinstance(row, dict)]


def route_model_count(payload: Any) -> int:
    if not isinstance(payload, dict):
        raise RouterContractError("invalid_model_list")
    models = payload.get("data")
    if not isinstance(models, list):
        raise RouterContractError("invalid_model_list")
    return sum(1 for model in models if isinstance(model, dict))


def subscription_status(
    connections: list[dict[str, Any]], provider: str
) -> dict[str, Any]:
    configured = [row for row in connections if row.get("provider") == provider]
    active = [
        row
        for row in configured
        if row.get("authType") in ALLOWED_SUBSCRIPTION_AUTH_TYPES
        and row.get("testStatus") == "active"
    ]
    return {
        "provider": provider,
        "status": "ready" if active else "not_configured",
        "configuredConnectionCount": len(configured),
        "activeSubscriptionConnectionCount": len(active),
    }


def evaluate(
    base_url: str,
    values: dict[str, str],
    *,
    require_subscriptions: tuple[str, ...] = (),
) -> dict[str, Any]:
    base_url = normalized_base_url(base_url)
    password = values.get("NINEROUTER_INITIAL_PASSWORD", "")
    if not password:
        raise RouterContractError("missing_ninerouter_initial_password")
    missing_keys = [key for key in PROFILE_KEY_REFS.values() if not values.get(key)]
    if missing_keys:
        raise RouterContractError("missing_profile_router_key")

    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    health = request_json(opener, "GET", f"{base_url}/api/health")
    if not isinstance(health, dict):
        raise RouterContractError("invalid_health_payload")
    login = request_json(
        opener,
        "POST",
        f"{base_url}/api/auth/login",
        body={"password": password},
    )
    if not isinstance(login, dict) or login.get("success") is not True:
        raise RouterContractError("dashboard_login_failed")
    connections = provider_connections(
        request_json(opener, "GET", f"{base_url}/api/providers")
    )

    routes: list[dict[str, Any]] = []
    for profile, key_ref in PROFILE_KEY_REFS.items():
        model_count = route_model_count(
            request_json(
                opener,
                "GET",
                f"{base_url}/v1/models",
                headers={"Authorization": f"Bearer {values[key_ref]}"},
            )
        )
        routes.append(
            {
                "profile": profile,
                "keyRef": key_ref,
                "status": "ready" if model_count else "no_models",
                "modelCount": model_count,
            }
        )

    subscriptions = [
        subscription_status(connections, provider)
        for provider in SUBSCRIPTION_PROVIDERS
    ]
    required = set(require_subscriptions)
    route_ready = all(row["status"] == "ready" for row in routes)
    subscriptions_ready = all(
        row["status"] == "ready"
        for row in subscriptions
        if row["provider"] in required
    )
    return {
        "status": "ready" if route_ready and subscriptions_ready else "needs_configuration",
        "health": {"status": "ready"},
        "profileRoutes": routes,
        "subscriptions": subscriptions,
        "subscriptionProvidersRequired": sorted(required),
    }


def arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument(
        "--require-subscription-provider",
        action="append",
        choices=SUBSCRIPTION_PROVIDERS,
        default=[],
        help="Fail unless the named provider has an active OAuth/access-token connection.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv or sys.argv[1:])
    try:
        result = evaluate(
            args.base_url,
            dotenv(args.env_file),
            require_subscriptions=tuple(args.require_subscription_provider),
        )
    except (OSError, RouterContractError) as error:
        print(json.dumps({"status": "needs_configuration", "error": str(error)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
