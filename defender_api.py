"""Microsoft Defender API client.

The first real rest_api transport. Authenticates to the Defender for Endpoint
API using the AISOC-Defender-Reader app registration, with the client secret
pulled from Key Vault at runtime — never hardcoded, never in the repo.

Cloud-aware endpoints:
  commercial  -> https://api.securitycenter.microsoft.com
  government  -> https://api-gov.securitycenter.microsoft.us
Token audience differs per cloud too. All configuration comes from the customer
profile (extra.defender) plus the secret in Key Vault, so a new customer is
onboarded by configuration, not code.

This module is the pattern every future external API source (Google TI,
VirusTotal, MISP) will follow: identity + endpoint from config, secret from Key
Vault, results normalised to the registry's shape.
"""

from __future__ import annotations

import time
from functools import lru_cache
from typing import Any

import requests

from customer import customer
import kv_secrets

# Per-cloud Defender API base and OAuth token host.
_DEFENDER = {
    "commercial": {
        "api": "https://api.securitycenter.microsoft.com",
        "resource": "https://api.securitycenter.microsoft.com",
        "login": "https://login.microsoftonline.com",
    },
    "government": {
        "api": "https://api-gov.securitycenter.microsoft.us",
        "resource": "https://api-gov.securitycenter.microsoft.us",
        "login": "https://login.microsoftonline.us",
    },
}

_token_cache: dict[str, Any] = {"token": None, "expires": 0}


def _cfg() -> dict:
    d = customer().extra.get("defender") or {}
    missing = [k for k in ("client_id", "tenant_id", "secret_name") if not d.get(k)]
    if missing:
        raise RuntimeError(f"customer '{customer().name}' defender config missing: {missing}. "
                           f"Add extra.defender with client_id, tenant_id, secret_name.")
    return d


def _endpoints() -> dict:
    return _DEFENDER.get(customer().cloud, _DEFENDER["commercial"])


def _token() -> str:
    """Client-credentials token for the Defender API, cached until near expiry.
    The client secret is read from Key Vault, not stored anywhere in the app."""
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires"] - 60:
        return _token_cache["token"]

    cfg = _cfg()
    ep = _endpoints()
    secret = kv_secrets.get_secret(cfg["secret_name"])
    resp = requests.post(
        f"{ep['login']}/{cfg['tenant_id']}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": cfg["client_id"],
            "client_secret": secret,
            "scope": f"{ep['resource']}/.default",
        },
        timeout=30,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"defender token failed {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    _token_cache["token"] = data["access_token"]
    _token_cache["expires"] = now + int(data.get("expires_in", 3600))
    return _token_cache["token"]


def _get(path: str, params: dict | None = None) -> dict[str, Any]:
    """GET a Defender API path. Read-only; the app has only Ti.Read.All."""
    ep = _endpoints()
    resp = requests.get(
        f"{ep['api']}{path}",
        headers={"Authorization": f"Bearer {_token()}"},
        params=params or {},
        timeout=30,
    )
    if resp.status_code >= 400:
        return {"available": False, "reason": f"defender API {resp.status_code}: {resp.text[:200]}",
                "rows": []}
    body = resp.json()
    rows = body.get("value", body if isinstance(body, list) else [body])
    return {"available": True, "kind": "rest_api", "source": "defender", "row_count": len(rows),
            "rows": rows}


# --- indicator queries ------------------------------------------------------

def list_indicators(top: int = 50) -> dict[str, Any]:
    """The organization's custom threat indicators (blocklists/allowlists)."""
    return _get("/api/indicators", params={"$top": top})


def match_indicator(value: str) -> dict[str, Any]:
    """Is a specific IP / domain / URL / hash on the org's indicator list?"""
    safe = value.replace("'", "")
    r = _get("/api/indicators", params={"$filter": f"indicatorValue eq '{safe}'"})
    if r.get("available"):
        r["indicator"] = value
        r["on_indicator_list"] = r.get("row_count", 0) > 0
    return r


if __name__ == "__main__":
    import json, sys
    # Smoke test: fetch a page of indicators to prove auth + endpoint work.
    try:
        result = list_indicators(top=5)
        print(json.dumps({"available": result.get("available"),
                          "count": result.get("row_count"),
                          "reason": result.get("reason")}, indent=2))
        if result.get("rows"):
            print("sample keys:", list(result["rows"][0].keys())[:10])
    except Exception as e:  # noqa: BLE001
        print("failed:", e)
