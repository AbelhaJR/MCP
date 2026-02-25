import azure.functions as func
import base64
import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any

IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"

MAX_ROWS = 200
DEFAULT_ROWS = 50
MAX_HOURS = 24


# =====================================================
# Utilities (Your original logic untouched)
# =====================================================

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def parse_timespan_to_hours(timespan: str) -> float:
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan)
    if m:
        return int(m.group(1) or 0) + int(m.group(2) or 0) / 60.0
    d = re.fullmatch(r"P(\d+)D", timespan)
    if d:
        return int(d.group(1)) * 24.0
    raise ValueError("Invalid timespan format")

def kql_safety_check(kql: str):
    lowered = kql.lower()
    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad")
    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = kql.lower()
    if " take " in lowered or " limit " in lowered:
        return kql
    return f"{kql}\n| take {limit}"


# =====================================================
# Managed Identity Token
# =====================================================

def get_managed_identity_token(resource: str) -> str:
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER")

    if identity_endpoint and identity_header:
        url = f"{identity_endpoint}?resource={resource}&api-version=2019-08-01"
        req = urllib.request.Request(
            url,
            headers={"X-IDENTITY-HEADER": identity_header, "Metadata": "true"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())["access_token"]

    # IMDS fallback
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())["access_token"]


# =====================================================
# Log Analytics Query
# =====================================================

def query_log_analytics(workspace_id: str, kql: str, timespan: str, token: str):
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"

    payload = {"query": kql, "timespan": timespan}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())


# =====================================================
# MCP Entry Point
# =====================================================

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
        method = body.get("method")
        request_id = body.get("id")

        # ---------------- INITIALIZE ----------------
        if method == "initialize":
            return _rpc_response(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sentinel-mcp", "version": "1.0.0"}
            })

        # ---------------- TOOLS LIST ----------------
        if method == "tools/list":
            return _rpc_response(request_id, {
                "tools": [
                    {
                        "name": "query_log_analytics",
                        "description": "Execute bounded KQL query against Log Analytics",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "kql": {"type": "string"},
                                "timespan": {"type": "string", "default": "PT1H"},
                                "max_rows": {"type": "integer", "default": 50}
                            },
                            "required": ["kql"]
                        }
                    }
                ]
            })

        # ---------------- TOOLS CALL ----------------
        if method == "tools/call":
            params = body.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})

            if tool_name != "query_log_analytics":
                return _rpc_error(request_id, -32601, "Tool not found")

            workspace_id = os.environ.get("WORKSPACE_ID")
            if not workspace_id:
                return _rpc_error(request_id, -32000, "WORKSPACE_ID not configured")

            kql = args.get("kql")
            timespan = args.get("timespan", "PT1H")
            max_rows = int(args.get("max_rows", DEFAULT_ROWS))

            if not kql:
                return _rpc_error(request_id, -32602, "Missing 'kql'")

            max_rows = max(1, min(max_rows, MAX_ROWS))
            hours = parse_timespan_to_hours(timespan)
            if hours > MAX_HOURS:
                return _rpc_error(request_id, -32602, "Timespan exceeds 24h")

            kql_safety_check(kql)
            kql = ensure_take_limit(kql, max_rows)

            token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)
            data = query_log_analytics(workspace_id, kql, timespan, token)

            return _rpc_response(request_id, {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(data, indent=2)
                    }
                ]
            })

        return _rpc_error(request_id, -32601, "Method not found")

    except Exception as e:
        return _rpc_error(body.get("id") if body else None, -32000, str(e))


# =====================================================
# JSON-RPC Helpers
# =====================================================

def _rpc_response(request_id, result):
    return func.HttpResponse(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}),
        status_code=200,
        mimetype="application/json",
    )

def _rpc_error(request_id, code, message):
    return func.HttpResponse(
        json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message}
        }),
        status_code=200,
        mimetype="application/json",
    )
