import azure.functions as func
import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple

# ---------------------------
# Config
# ---------------------------
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"

WORKSPACE_ID_ENV = "WORKSPACE_ID"

MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50
MAX_HOURS = 24  # hard cap for safety
DEFAULT_TIMESPAN = "PT1H"

# If you want to restrict tables for safety, add allowed prefixes or explicit allowlist.
# Example allowlist:
# ALLOWED_TABLES = {"SecurityAlert", "SecurityIncident", "SigninLogs", "DeviceProcessEvents", "Heartbeat"}
ALLOWED_TABLES = None  # set to a set(...) to enforce

# ---------------------------
# JSON-RPC helpers
# ---------------------------
def rpc_ok(request_id: Any, result: Dict[str, Any]) -> func.HttpResponse:
    payload = {"jsonrpc": "2.0", "id": request_id, "result": result}
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False), status_code=200, mimetype="application/json")

def rpc_err(request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> func.HttpResponse:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    payload = {"jsonrpc": "2.0", "id": request_id, "error": err}
    return func.HttpResponse(json.dumps(payload, ensure_ascii=False), status_code=200, mimetype="application/json")

# ---------------------------
# Guardrails / parsing
# ---------------------------
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

def clamp_rows(n: Any) -> int:
    try:
        v = int(n)
    except Exception:
        v = DEFAULT_ROWS
    return max(1, min(v, MAX_ROWS_HARD))

def kql_safety_check(kql: str) -> None:
    lowered = kql.lower()

    # block super broad
    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' is not allowed")

    # block risky/heavy operators (tune to your environment)
    blocked_ops = ["externaldata", "evaluate", "make-series", "mv-expand"]
    for op in blocked_ops:
        if op in lowered:
            raise ValueError(f"KQL contains blocked operator: {op}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = kql.lower()
    if " take " in lowered or " limit " in lowered or "|take" in lowered or "|limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

def extract_first_table_name(kql: str) -> Optional[str]:
    """
    Best-effort: attempts to infer the first table referenced (e.g., 'SecurityAlert | ...').
    This helps enforce allowlists.
    """
    # strip comments and whitespace
    s = re.sub(r"//.*", "", kql).strip()
    # first token until whitespace or pipe
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\||$)", s)
    if not m:
        return None
    return m.group(1)

def enforce_table_allowlist(kql: str) -> None:
    if not ALLOWED_TABLES:
        return
    table = extract_first_table_name(kql)
    if table and table not in ALLOWED_TABLES:
        raise ValueError(f"Table '{table}' is not allowed by policy")

# ---------------------------
# Managed Identity token (no azure-identity)
# ---------------------------
def get_managed_identity_token(resource: str) -> str:
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER") or os.environ.get("MSI_SECRET")
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")  # optional user-assigned MI

    # Functions/App Service endpoint
    if identity_endpoint and identity_header:
        sep = "&" if "?" in identity_endpoint else "?"
        extra = f"&client_id={client_id}" if client_id else ""
        url = f"{identity_endpoint}{sep}resource={resource}&api-version=2019-08-01{extra}"
        req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": identity_header, "Metadata": "true"}, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))["access_token"]

    # IMDS fallback
    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]

# ---------------------------
# Log Analytics API
# ---------------------------
def la_query(workspace_id: str, kql: str, timespan: str, token: str) -> Dict[str, Any]:
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": kql, "timespan": timespan}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-ms-app": "mcp-sentinel-gateway",
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode("utf-8"))

def parse_la_http_error(e: urllib.error.HTTPError) -> Dict[str, Any]:
    body_raw = e.read().decode("utf-8", errors="replace")
    try:
        body = json.loads(body_raw)
    except Exception:
        body = {"raw": body_raw}
    return {"status": e.code, "body": body}

def classify_la_error(details: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    """
    Returns (error_type, message, suggestions)
    Designed so the agent can adapt (e.g., call get_table_schema).
    """
    status = details.get("status")
    body = details.get("body", {})
    err = body.get("error") if isinstance(body, dict) else None
    msg = ""
    code = ""
    if isinstance(err, dict):
        msg = err.get("message", "") or ""
        code = err.get("code", "") or ""

    suggestions: List[str] = []
    error_type = "Unknown"

    # Typical schema errors are "BadArgumentError" or semantic errors in message text
    text = (msg or "").lower()

    if status == 400:
        if "failed to resolve table" in text or "unknown table" in text or "does not refer to any known table" in text:
            error_type = "TableNotFound"
            suggestions = ["Call list_tables to find the correct table name.", "Call preview_table for a likely candidate."]
        elif "failed to resolve column" in text or "unknown column" in text or "does not refer to any known column" in text:
            error_type = "ColumnNotFound"
            suggestions = ["Call get_table_schema to discover the correct column name.", "Call preview_table to inspect sample rows."]
        elif "syntax" in text or "parse" in text:
            error_type = "KqlSyntaxError"
            suggestions = ["Simplify the query and retry.", "Try running preview_table first."]
        else:
            error_type = "BadRequest"
            suggestions = ["Try preview_table or get_table_schema, then retry with corrected table/column names."]

    if status == 403 or code.lower() == "insufficientaccesserror":
        error_type = "AccessDenied"
        suggestions = [
            "Verify the Function App managed identity has permission to query the workspace.",
            "Check workspace access control mode and role assignments.",
        ]

    if status in (429, 503, 504):
        error_type = "Transient"
        suggestions = ["Retry the same query after a short delay.", "Reduce timespan and/or max_rows."]

    return error_type, (msg or "Log Analytics request failed"), suggestions

def table_from_union_source_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert LA response (tables/columns/rows) to list of dicts (first table only)."""
    tables = data.get("tables", [])
    if not tables:
        return []
    t0 = tables[0]
    cols = [c.get("name") for c in t0.get("columns", [])]
    rows = t0.get("rows", [])
    out = []
    for r in rows:
        item = {}
        for i, name in enumerate(cols):
            item[name] = r[i] if i < len(r) else None
        out.append(item)
    return out

# ---------------------------
# Tool implementations
# ---------------------------
def tool_list_tables(workspace_id: str, token: str, timespan: str) -> Dict[str, Any]:
    # “union withsource” over * can be heavy. Keep small timespan and take.
    kql = """
union withsource=TableName *
| summarize Count=count() by TableName
| top 200 by Count desc
"""
    data = la_query(workspace_id, kql, timespan, token)
    rows = table_from_union_source_results(data)
    return {"tables": rows}

def tool_get_table_schema(workspace_id: str, token: str, table: str, timespan: str) -> Dict[str, Any]:
    # getschema ignores timespan mostly but API requires it
    kql = f"{table} | getschema"
    data = la_query(workspace_id, kql, timespan, token)
    rows = table_from_union_source_results(data)
    return {"table": table, "schema": rows}

def tool_preview_table(workspace_id: str, token: str, table: str, timespan: str, max_rows: int) -> Dict[str, Any]:
    kql = f"{table} | take {max_rows}"
    data = la_query(workspace_id, kql, timespan, token)
    rows = table_from_union_source_results(data)
    return {"table": table, "preview": rows}

def tool_run_query(workspace_id: str, token: str, kql: str, timespan: str, max_rows: int) -> Dict[str, Any]:
    kql_safety_check(kql)
    enforce_table_allowlist(kql)

    # enforce bounds
    hours = parse_timespan_to_hours(timespan)
    if hours <= 0 or hours > MAX_HOURS:
        raise ValueError(f"timespan exceeds max allowed window ({MAX_HOURS}h)")

    kql_limited = ensure_take_limit(kql, max_rows)

    data = la_query(workspace_id, kql_limited, timespan, token)
    rows = table_from_union_source_results(data)

    return {
        "meta": {
            "timespan": timespan,
            "max_rows": max_rows,
            "note": "Query bounded by server policy (take/limit enforced if missing)."
        },
        "result": rows
    }

# ---------------------------
# MCP main router
# ---------------------------
def main(req: func.HttpRequest) -> func.HttpResponse:
    request_id = None
    try:
        body = req.get_json()
        request_id = body.get("id")
        method = body.get("method")

        # MCP initialize
        if method == "initialize":
            return rpc_ok(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sentinel-mcp-pro", "version": "1.0.0"}
            })

        # tools/list
        if method == "tools/list":
            return rpc_ok(request_id, {
                "tools": [
                    {
                        "name": "run_query",
                        "description": "Run a bounded KQL query against Log Analytics with safety guardrails and structured output.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "kql": {"type": "string"},
                                "timespan": {"type": "string", "default": DEFAULT_TIMESPAN},
                                "max_rows": {"type": "integer", "default": DEFAULT_ROWS}
                            },
                            "required": ["kql"]
                        }
                    },
                    {
                        "name": "list_tables",
                        "description": "List tables with event counts (bounded). Useful when a table name is unknown.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "timespan": {"type": "string", "default": "PT1H"}
                            }
                        }
                    },
                    {
                        "name": "get_table_schema",
                        "description": "Return column schema for a given table (via getschema). Useful when a column name is unknown.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"},
                                "timespan": {"type": "string", "default": DEFAULT_TIMESPAN}
                            },
                            "required": ["table"]
                        }
                    },
                    {
                        "name": "preview_table",
                        "description": "Preview a few rows from a table (bounded). Useful to confirm schema and sample values.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"},
                                "timespan": {"type": "string", "default": DEFAULT_TIMESPAN},
                                "max_rows": {"type": "integer", "default": 10}
                            },
                            "required": ["table"]
                        }
                    }
                ]
            })

        # tools/call
        if method == "tools/call":
            params = body.get("params", {}) or {}
            tool_name = params.get("name")
            args = params.get("arguments", {}) or {}

            workspace_id = os.environ.get(WORKSPACE_ID_ENV)
            if not workspace_id:
                return rpc_err(request_id, -32000, f"{WORKSPACE_ID_ENV} not configured")

            token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

            try:
                if tool_name == "run_query":
                    kql = args.get("kql")
                    if not kql:
                        return rpc_err(request_id, -32602, "Missing 'kql'")
                    timespan = args.get("timespan", DEFAULT_TIMESPAN)
                    max_rows = clamp_rows(args.get("max_rows", DEFAULT_ROWS))
                    result = tool_run_query(workspace_id, token, kql, timespan, max_rows)
                    return rpc_ok(request_id, {"content": [{"type": "json", "data": result}]})

                if tool_name == "list_tables":
                    timespan = args.get("timespan", "PT1H")
                    # keep list_tables bounded even tighter than general queries
                    if parse_timespan_to_hours(timespan) > 2:
                        timespan = "PT2H"
                    result = tool_list_tables(workspace_id, token, timespan)
                    return rpc_ok(request_id, {"content": [{"type": "json", "data": result}]})

                if tool_name == "get_table_schema":
                    table = args.get("table")
                    if not table:
                        return rpc_err(request_id, -32602, "Missing 'table'")
                    timespan = args.get("timespan", DEFAULT_TIMESPAN)
                    result = tool_get_table_schema(workspace_id, token, table, timespan)
                    return rpc_ok(request_id, {"content": [{"type": "json", "data": result}]})

                if tool_name == "preview_table":
                    table = args.get("table")
                    if not table:
                        return rpc_err(request_id, -32602, "Missing 'table'")
                    timespan = args.get("timespan", DEFAULT_TIMESPAN)
                    max_rows = max(1, min(int(args.get("max_rows", 10)), 50))
                    result = tool_preview_table(workspace_id, token, table, timespan, max_rows)
                    return rpc_ok(request_id, {"content": [{"type": "json", "data": result}]})

                return rpc_err(request_id, -32601, f"Tool not found: {tool_name}")

            except urllib.error.HTTPError as e:
                details = parse_la_http_error(e)
                etype, msg, suggestions = classify_la_error(details)
                return rpc_err(
                    request_id,
                    -32000,
                    msg,
                    data={
                        "error_type": etype,
                        "http_status": details.get("status"),
                        "suggestions": suggestions,
                        "log_analytics_error": details.get("body"),
                        "next_best_actions": _next_actions_for_error_type(etype)
                    }
                )

            except Exception as e:
                return rpc_err(request_id, -32000, str(e), data={"error_type": "ToolExecutionError"})

        return rpc_err(request_id, -32601, f"Method not found: {method}")

    except Exception as e:
        return rpc_err(request_id, -32000, str(e), data={"error_type": "ServerError"})


def _next_actions_for_error_type(error_type: str) -> List[str]:
    # This is deliberately explicit so the agent "knows what to do next".
    if error_type == "TableNotFound":
        return ["list_tables", "preview_table", "get_table_schema"]
    if error_type == "ColumnNotFound":
        return ["get_table_schema", "preview_table"]
    if error_type == "KqlSyntaxError":
        return ["preview_table", "run_query"]
    if error_type == "AccessDenied":
        return ["Check RBAC and workspace access control mode", "Confirm managed identity client id", "Try Heartbeat | take 5"]
    if error_type == "Transient":
        return ["Retry", "Reduce timespan", "Reduce max_rows"]
    return ["list_tables", "get_table_schema", "preview_table"]
