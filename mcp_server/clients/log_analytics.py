from __future__ import annotations

import time
from typing import Any

import requests

from ..config import Settings
from ..responses import fail, ok

LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
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


def query_workspace(settings: Settings, kql: str, timespan: str) -> dict:
    if not settings.workspace_id:
        return fail("CONFIG_ERROR", "WORKSPACE_ID is not configured")

    url = f"https://api.loganalytics.io/v1/workspaces/{settings.workspace_id}/query"
    token = _get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"query": kql, "timespan": timespan},
        timeout=settings.la_http_timeout,
    )

    if response.status_code >= 400:
        return fail(
            "LOG_ANALYTICS_ERROR",
            f"Log Analytics query failed with HTTP {response.status_code}",
            detail=response.text[:1500],
            timespan=timespan,
        )

    try:
        return ok(response.json(), timespan=timespan)
    except Exception as exc:
        return fail(
            "PARSE_ERROR",
            "Failed to parse Log Analytics response",
            detail=str(exc),
            timespan=timespan,
        )