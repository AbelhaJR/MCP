import azure.functions as func
import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, Tuple, List

# ============================
# Configuration
# ============================

IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
WORKSPACE_ID_ENV = "WORKSPACE_ID"

MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50
MAX_HOURS = 24
DEFAULT_TIMESPAN = "PT1H"

# ============================
# JSON-RPC Helpers
# ============================

def rpc_ok(request_id: Any, result: Dict[str, Any]) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result
        }, ensure_ascii=False),
        status_code=200,
        mimetype="application/json"
    )

def rpc_err(request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> func.HttpResponse:
    err = {"code": code, "message": message}
    if data:
        err["data"] = data

    return func.HttpResponse(
        json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": err
        }, ensure_ascii=False),
        status_code=200,
        mimetype="application/json"
    )

# ============================
# Guardrails
# ============================

def parse_timespan_to_hours(timespan: str) -> float:
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan)
    if m:
        return int(m.group(1) or 0) + int(m.group(2) or 0) / 60.0
    d = re.fullmatch(r"P(\d+)D", timespan)
    if d:
        return int(d.group(1)) * 24.0
    raise ValueError("Invalid timespan format")

def clamp_rows(n: Any) -> int:
    try:
        v = int(n)
    except Exception:
        v = DEFAULT_ROWS
    return max(1, min(v, MAX_ROWS_HARD))

def kql_safety_check(kql: str):
    lowered = kql.lower()

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' not allowed")

    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = kql.lower()
    if " take " in lowered or " limit " in lowered or "|take" in lowered or "|limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

# ============================
# Managed Identity
# ============================

def get_managed_identity_token(resource: str) -> str:
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER") or os.environ.get("MSI_SECRET")
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")

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
            return json.loads(resp.read().decode())["access_token"]

    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")

    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())["access_token"]

# ============================
# Log Analytics
# ============================

def la_query(workspace_id: str, kql: str, timespan: str, token: str) -> Dict[str, Any]:
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"

    payload = {"query": kql, "timespan": timespan}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())

# ============================
# Tools
# ============================

def run_query_tool(workspace_id, token, kql, timespan, max_rows):
    kql_safety_check(kql)
    hours = parse_timespan_to_hours(timespan)
    if hours <= 0 or hours > MAX_HOURS:
        raise ValueError("Timespan exceeds allowed window")
    kql = ensure_take_limit(kql, max_rows)
    return la_query(workspace_id, kql, timespan, token)

def list_tables_tool(workspace_id, token, timespan):
    kql = """
    union withsource=TableName *
    | summarize Count=count() by TableName
    | top 200 by Count desc
    """
    return la_query(workspace_id, kql, timespan, token)

def get_schema_tool(workspace_id, token, table):
    return la_query(workspace_id, f"{table} | getschema", DEFAULT_TIMESPAN, token)

def preview_table_tool(workspace_id, token, table):
    return la_query(workspace_id, f"{table} | take 10", DEFAULT_TIMESPAN, token)

# ============================
# MCP Entry
# ============================

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
        request_id = body.get("id")
        method = body.get("method")

        if method == "initialize":
            return rpc_ok(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sentinel-mcp-pro", "version": "1.0.0"}
            })

        if method == "tools/list":
            return rpc_ok(request_id, {
                "tools": [
                    {
                        "name": "run_query",
                        "description": "Run a bounded KQL query",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "kql": {"type": "string"},
                                "timespan": {"type": "string"},
                                "max_rows": {"type": "integer"}
                            },
                            "required": ["kql"]
                        }
                    },
                    {
                        "name": "list_tables",
                        "description": "List active tables in workspace",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "timespan": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "get_table_schema",
                        "description": "Get table schema",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"}
                            },
                            "required": ["table"]
                        }
                    },
                    {
                        "name": "preview_table",
                        "description": "Preview rows from table",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"}
                            },
                            "required": ["table"]
                        }
                    }
                ]
            })

        if method == "tools/call":
            params = body.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {}) or {}

            workspace_id = os.environ.get(WORKSPACE_ID_ENV)
            if not workspace_id:
                return rpc_err(request_id, -32000, "WORKSPACE_ID not configured")

            token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

            if tool_name == "run_query":
                result = run_query_tool(
                    workspace_id,
                    token,
                    args.get("kql"),
                    args.get("timespan", DEFAULT_TIMESPAN),
                    clamp_rows(args.get("max_rows", DEFAULT_ROWS))
                )

            elif tool_name == "list_tables":
                result = list_tables_tool(
                    workspace_id,
                    token,
                    args.get("timespan", DEFAULT_TIMESPAN)
                )

            elif tool_name == "get_table_schema":
                result = get_schema_tool(workspace_id, token, args.get("table"))

            elif tool_name == "preview_table":
                result = preview_table_tool(workspace_id, token, args.get("table"))

            else:
                return rpc_err(request_id, -32601, "Tool not found")

            return rpc_ok(request_id, {
                "content": [{
                    "type": "text",
                    "text": json.dumps(result, ensure_ascii=False, indent=2)
                }]
            })

        return rpc_err(request_id, -32601, "Method not found")

    except Exception as e:
        return rpc_err(None, -32000, str(e))
