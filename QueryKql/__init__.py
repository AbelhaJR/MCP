import azure.functions as func
import base64
import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"

MAX_ROWS = 200
DEFAULT_ROWS = 50
MAX_HOURS = 24

DEBUG_AUTH = os.environ.get("DEBUG_AUTH", "0") == "1"


# ---------------------------
# Utilities
# ---------------------------

def _json_response(obj: Dict[str, Any], status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(obj, ensure_ascii=False),
        status_code=status,
        mimetype="application/json",
    )

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def decode_jwt_claims(token: str) -> Dict[str, Any]:
    """Decode JWT payload without verifying signature (debug only)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        return json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return {}

def parse_timespan_to_hours(timespan: str) -> float:
    # PT#H#M
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan)
    if m:
        return int(m.group(1) or 0) + int(m.group(2) or 0) / 60.0
    # P#D
    d = re.fullmatch(r"P(\d+)D", timespan)
    if d:
        return int(d.group(1)) * 24.0
    raise ValueError("timespan must be PT#M, PT#H, or P#D (e.g., PT15M, PT1H, P1D)")

def kql_safety_check(kql: str):
    lowered = kql.lower()

    # Block super-broad query
    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' is not allowed")

    # Block a few heavier / risky operators (tune as needed)
    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = kql.lower()
    # If user already limits, respect it
    if " take " in lowered or " limit " in lowered or "|take" in lowered or "|limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

def is_guid(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s or ""))


# ---------------------------
# Managed Identity token
# ---------------------------

def get_managed_identity_token(resource: str) -> Dict[str, Any]:
    """
    Get Managed Identity token without azure-identity.
    Supports:
      - IDENTITY_ENDPOINT + IDENTITY_HEADER (Functions/App Service)
      - MSI_ENDPOINT + MSI_SECRET (legacy)
      - IMDS fallback
    Supports user-assigned identity via MANAGED_IDENTITY_CLIENT_ID.
    """
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER") or os.environ.get("MSI_SECRET")
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")  # optional

    # Preferred: Identity endpoint exposed in Functions/App Service
    if identity_endpoint and identity_header:
        sep = "&" if "?" in identity_endpoint else "?"
        extra = f"&client_id={client_id}" if client_id else ""
        url = f"{identity_endpoint}{sep}resource={resource}&api-version=2019-08-01{extra}"

        req = urllib.request.Request(
            url,
            headers={"X-IDENTITY-HEADER": identity_header, "Metadata": "true"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            token = payload["access_token"]
            result = {"access_token": token, "obtained_via": "IDENTITY_ENDPOINT"}
            if DEBUG_AUTH:
                result["claims"] = decode_jwt_claims(token)
            return result

    # Fallback: IMDS
    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        token = payload["access_token"]
        result = {"access_token": token, "obtained_via": "IMDS"}
        if DEBUG_AUTH:
            result["claims"] = decode_jwt_claims(token)
        return result


# ---------------------------
# Log Analytics query
# ---------------------------

def query_log_analytics(workspace_id: str, kql: str, timespan: str, token: str) -> Dict[str, Any]:
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": kql, "timespan": timespan}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        # sometimes helps tenants / app-only flows
        "x-ms-app": "mcp-sentinel-gateway",
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_log_analytics_http_error(e: urllib.error.HTTPError) -> Dict[str, Any]:
    """
    Log Analytics often returns JSON like:
    {"error":{"message":"...","code":"InsufficientAccessError","correlationId":"..."}}
    """
    body = e.read().decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = {"raw": body}

    return {
        "status": e.code,
        "headers": dict(e.headers.items()) if e.headers else {},
        "body": parsed,
    }


# ---------------------------
# Function entrypoint
# ---------------------------

def main(req: func.HttpRequest) -> func.HttpResponse:
    # You call this endpoint yourself; body contains kql/timespan/max_rows
    # Optional: "debug": true in the body enables extra hints in response (still safer than DEBUG_AUTH)
    try:
        workspace_id = os.environ.get("WORKSPACE_ID")
        if not workspace_id:
            return _json_response({"error": "WORKSPACE_ID not configured"}, 500)

        # sanity check workspace id format
        workspace_id_ok = is_guid(workspace_id)

        body = req.get_json()
        kql = body.get("kql")
        timespan = body.get("timespan", "PT1H")
        max_rows = int(body.get("max_rows", DEFAULT_ROWS))
        debug = bool(body.get("debug", False))

        if not kql:
            return _json_response({"error": "Missing 'kql' in request body"}, 400)

        # Apply bounds
        max_rows = max(1, min(max_rows, MAX_ROWS))
        hours = parse_timespan_to_hours(timespan)
        if hours <= 0 or hours > MAX_HOURS:
            return _json_response({"error": "timespan exceeds max allowed window (24h)"}, 400)

        kql_safety_check(kql)
        kql = ensure_take_limit(kql, max_rows)

        # Get MI token
        token_info = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)
        token = token_info["access_token"]

        # Run query
        data = query_log_analytics(workspace_id, kql, timespan, token)

        resp = {
            "meta": {
                "timespan": timespan,
                "max_rows": max_rows,
                "workspace_id_is_guid": workspace_id_ok,
                "note": "Bounded result",
            },
            "data": data,
        }

        # Safe-ish debug info (not the token)
        if debug:
            resp["debug"] = {
                "identity_obtained_via": token_info.get("obtained_via"),
                "managed_identity_client_id_configured": bool(os.environ.get("MANAGED_IDENTITY_CLIENT_ID")),
                "workspace_id_hint": "Workspace ID must be the GUID from the workspace properties (not the Azure resource ID).",
            }
            if DEBUG_AUTH and "claims" in token_info:
                claims = token_info["claims"]
                # Show only the key identity fields
                resp["debug"]["token_claims"] = {
                    "tid": claims.get("tid"),
                    "oid": claims.get("oid"),
                    "appid": claims.get("appid"),
                    "xms_mirid": claims.get("xms_mirid"),  # often shows the managed identity resource id
                }

        return _json_response(resp, 200)

    except urllib.error.HTTPError as e:
        error_details = parse_log_analytics_http_error(e)

        # Provide strong hints for the most common failures
        hints = []
        body = error_details.get("body", {})
        err = body.get("error") if isinstance(body, dict) else None
        code = (err or {}).get("code") if isinstance(err, dict) else None

        if code == "InsufficientAccessError":
            hints = [
                "This usually means the identity in the token does not have permission to QUERY this workspace.",
                "Check Log Analytics Workspace 'Access control mode': if it's set to 'Require workspace permissions' (legacy), Azure RBAC roles like 'Log Analytics Reader' may not grant query access.",
                "Verify the role assignment is applied to the MANAGED IDENTITY PRINCIPAL (Object ID), not just the Function App resource.",
                "If you have both system-assigned and user-assigned identities, ensure your token is coming from the identity you granted access to (set MANAGED_IDENTITY_CLIENT_ID if needed).",
                "Confirm WORKSPACE_ID is the Workspace GUID, not the Azure Resource ID.",
                "Try a minimal query like: Heartbeat | take 5 to validate base workspace access.",
            ]

        return _json_response(
            {
                "error": "Log Analytics query failed",
                "details": error_details,
                "hints": hints,
            },
            status=error_details.get("status", 500),
        )

    except urllib.error.URLError as e:
        return _json_response({"error": f"url error: {str(e)}"}, 500)

    except Exception as e:
        return _json_response({"error": str(e)}, 500)
