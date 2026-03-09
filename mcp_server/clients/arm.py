from __future__ import annotations

import time
from typing import Any

import requests

from ..config import Settings
from ..responses import fail, ok

ARM_RESOURCE = "https://management.azure.com/"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
_TOKEN_CACHE: dict[str, dict[str, Any]] = {}


def _get_managed_identity_token(resource: str) -> str:
    now = int(time.time())
    cached = _TOKEN_CACHE.get(resource)
    if cached and cached["exp"] - now > 60:
        return cached["token"]

    response = requests.get(
        IMDS_ENDPOINT,
        params={"api-version": "2018-02-01", "resource": resource},
        headers={"Metadata": "true"},
        timeout=5,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload["access_token"]
    expires_on = int(payload.get("expires_on", now + 300))
    _TOKEN_CACHE[resource] = {"token": token, "exp": expires_on}
    return token


def arm_get(settings: Settings, path: str, api_version: str) -> dict:
    token = _get_managed_identity_token(ARM_RESOURCE)
    url = f"https://management.azure.com{path}"

    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params={"api-version": api_version},
        timeout=settings.la_http_timeout,
    )

    if response.status_code >= 400:
        return fail(
            "ARM_ERROR",
            f"ARM GET failed with HTTP {response.status_code}",
            detail=response.text[:1500],
        )

    try:
        return ok(response.json())
    except Exception as exc:
        return fail("PARSE_ERROR", "Failed to parse ARM response", detail=str(exc))