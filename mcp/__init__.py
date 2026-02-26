import azure.functions as func
import json
import os
import re
import time
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

# Log Analytics call hardening
LA_TIMEOUT_SECONDS = 60
LA_MAX_RETRIES_429 = 4           # total attempts = 4
LA_BACKOFF_BASE_SECONDS = 2      # 2,4,8...


# ============================
# JSON-RPC Helpers
# ============================

def rpc_ok(request_id: Any, result: Dict[str, Any]) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, ensure_ascii=False),
        status_code=200,
        mimetype="application/json",
    )

def rpc_err(request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> func.HttpResponse:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return func.HttpResponse(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "error": err}, ensure_ascii=False),
        status_code=200,
        mimetype="application/json",
    )


# ============================
# Guardrails / utilities
# ============================

def parse_timespan_to_hours(timespan: str) -> float:
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan or "")
    if m:
        return int(m.group(1) or 0) + int(m.group(2) or 0) / 60.0
    d = re.fullmatch(r"P(\d+)D", timespan or "")
    if d:
        return int(d.group(1)) * 24.0
    raise ValueError("Invalid timespan format (use PT1H, PT30M, P1D, etc.)")

def clamp_rows(n: Any) -> int:
    try:
        v = int(n)
    except Exception:
        v = DEFAULT_ROWS
    return max(1, min(v, MAX_ROWS_HARD))

def kql_safety_check(kql: str) -> None:
    lowered = (kql or "").lower()

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' not allowed")

    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = (kql or "").lower()
    if " take " in lowered or " limit " in lowered or "|take" in lowered or "|limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"


# ============================
# Managed Identity token
# ============================

def get_managed_identity_token(resource: str) -> str:
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER") or os.environ.get("MSI_SECRET")
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")

    # Functions/App Service endpoint
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
            return json.loads(resp.read().decode("utf-8"))["access_token"]

    # IMDS fallback
    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


# ============================
# Log Analytics query (retry/backoff + larger timeout)
# ============================

def la_query(workspace_id: str, kql: str, timespan: str, token: str) -> Dict[str, Any]:
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": kql, "timespan": timespan}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-ms-app": "sentinel-mcp-pro",
    }

    last_error: Optional[str] = None

    for attempt in range(LA_MAX_RETRIES_429):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=LA_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except urllib.error.HTTPError as e:
            body_raw = e.read().decode("utf-8", errors="replace")
            last_error = body_raw

            # 429 throttling -> retry with backoff
            if e.code == 429 and attempt < LA_MAX_RETRIES_429 - 1:
                sleep_s = LA_BACKOFF_BASE_SECONDS * (2 ** attempt)
                time.sleep(sleep_s)
                continue

            # no more retries
            raise

        except Exception as e:
            # network/timeouts etc.
            last_error = str(e)
            raise

    # Should never hit
    raise RuntimeError(f"Log Analytics query failed after retries: {last_error}")


def parse_la_http_error(e: urllib.error.HTTPError) -> Dict[str, Any]:
    body_raw = e.read().decode("utf-8", errors="replace")
    try:
        body = json.loads(body_raw)
    except Exception:
        body = {"raw": body_raw}
    return {"status": e.code, "body": body}


def classify_la_error(details: Dict[str, Any]) -> Dict[str, Any]:
    status = details.get("status")
    body = details.get("body", {})
    msg = ""
    code = ""

    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = err.get("message", "") or ""
            code = err.get("code", "") or ""

    text = (msg or "").lower()

    error_type = "Unknown"
    suggestions: List[str] = []

    if status == 429:
        error_type = "TooManyRequests"
        suggestions = [
            "Retry later (throttling).",
            "Reduce the timespan (e.g., try 7d instead of 30d).",
            "Reduce result size and avoid heavy operators."
        ]
    elif status == 400:
        if "failed to resolve table" in text or "does not refer to any known table" in text:
            error_type = "TableNotFound"
            suggestions = ["Use list_tables then preview_table to confirm correct table name."]
        elif "failed to resolve column" in text or "does not refer to any known column" in text:
            error_type = "ColumnNotFound"
            suggestions = ["Use get_table_schema to find correct column names, then retry."]
        else:
            error_type = "BadRequest"
            suggestions = ["Try preview_table/get_table_schema and simplify the query."]
    elif status == 403 or (code.lower() == "insufficientaccesserror"):
        error_type = "AccessDenied"
        suggestions = ["Check Managed Identity permissions on the workspace."]
    elif status in (500, 502, 503, 504):
        error_type = "Transient"
        suggestions = ["Retry later.", "Reduce timespan/max_rows."]
    else:
        error_type = "HttpError"
        suggestions = ["Check query/table/columns and retry."]

    return {
        "error_type": error_type,
        "http_status": status,
        "message": msg or "Log Analytics request failed",
        "suggestions": suggestions,
        "raw": body,
    }


# ============================
# Tools
# ============================

def tool_run_query(workspace_id: str, token: str, kql: str, timespan: str, max_rows: int) -> Dict[str, Any]:
    if not kql:
        raise ValueError("Missing 'kql'")
    kql_safety_check(kql)

    hours = parse_timespan_to_hours(timespan)
    if hours <= 0 or hours > MAX_HOURS:
        raise ValueError(f"timespan exceeds allowed window ({MAX_HOURS}h). Use smaller timespan.")

    kql = ensure_take_limit(kql, max_rows)
    data = la_query(workspace_id, kql, timespan, token)
    return {
        "meta": {"timespan": timespan, "max_rows": max_rows},
        "data": data
    }

def tool_list_tables(workspace_id: str, token: str, timespan: str) -> Dict[str, Any]:
    # Lightweight approach using Usage (avoid union *)
    # Note: Usage might not exist in some workspaces; if it fails, user can still use preview_table/get_table_schema.
    kql = """
Usage
| where TimeGenerated > ago(24h)
| summarize Count=sum(Quantity) by DataType
| top 100 by Count desc
"""
    data = la_query(workspace_id, kql, timespan, token)
    return {"meta": {"timespan": timespan}, "data": data}

def tool_get_table_schema(workspace_id: str, token: str, table: str, timespan: str) -> Dict[str, Any]:
    if not table:
        raise ValueError("Missing 'table'")
    kql = f"{table} | getschema"
    data = la_query(workspace_id, kql, timespan, token)
    return {"meta": {"table": table, "timespan": timespan}, "data": data}

def tool_preview_table(workspace_id: str, token: str, table: str, timespan: str, take_rows: int) -> Dict[str, Any]:
    if not table:
        raise ValueError("Missing 'table'")
    take_rows = max(1, min(int(take_rows or 10), 50))
    kql = f"{table} | take {take_rows}"
    data = la_query(workspace_id, kql, timespan, token)
    return {"meta": {"table": table, "timespan": timespan, "take": take_rows}, "data": data}


# ============================
# MCP Entry Point
# ============================

def main(req: func.HttpRequest) -> func.HttpResponse:
    request_id = None
    try:
        body = req.get_json()
        request_id = body.get("id")
        method = body.get("method")

        # initialize
        if method == "initialize":
            return rpc_ok(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sentinel-mcp-pro", "version": "1.0.0"}
            })

        # tools/list
        if method == "tools/list":
            # Keep schemas SIMPLE for Copilot/.NET compatibility
            return rpc_ok(request_id, {
                "tools": [
                    {
                        "name": "run_query",
                        "description": "Run a bounded KQL query against Log Analytics",
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
                        "description": "List active tables (lightweight via Usage table)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "timespan": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "get_table_schema",
                        "description": "Get schema (columns) of a table",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"},
                                "timespan": {"type": "string"}
                            },
                            "required": ["table"]
                        }
                    },
                    {
                        "name": "preview_table",
                        "description": "Preview rows from a table (bounded)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "table": {"type": "string"},
                                "timespan": {"type": "string"},
                                "take": {"type": "integer"}
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
                return rpc_err(request_id, -32000, "WORKSPACE_ID not configured")

            try:
                token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

                if tool_name == "run_query":
                    result = tool_run_query(
                        workspace_id,
                        token,
                        args.get("kql"),
                        args.get("timespan", DEFAULT_TIMESPAN),
                        clamp_rows(args.get("max_rows", DEFAULT_ROWS))
                    )

                elif tool_name == "list_tables":
                    result = tool_list_tables(
                        workspace_id,
                        token,
                        args.get("timespan", DEFAULT_TIMESPAN)
                    )

                elif tool_name == "get_table_schema":
                    result = tool_get_table_schema(
                        workspace_id,
                        token,
                        args.get("table"),
                        args.get("timespan", DEFAULT_TIMESPAN)
                    )

                elif tool_name == "preview_table":
                    result = tool_preview_table(
                        workspace_id,
                        token,
                        args.get("table"),
                        args.get("timespan", DEFAULT_TIMESPAN),
                        args.get("take", 10)
                    )

                else:
                    return rpc_err(request_id, -32601, f"Tool not found: {tool_name}")

                # IMPORTANT: only 'text' blocks for .NET MCP client
                return rpc_ok(request_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(result, ensure_ascii=False, indent=2)
                    }]
                })

            except urllib.error.HTTPError as e:
                details = parse_la_http_error(e)
                classified = classify_la_error(details)
                return rpc_err(request_id, -32000, classified["message"], classified)

            except Exception as e:
                # NEVER let exceptions escape (prevents "no reply to request")
                return rpc_err(request_id, -32000, "Unhandled server exception", {
                    "details": str(e),
                    "hint": "If this happened on a heavy query, reduce timespan (e.g., 7d instead of 30d) or simplify KQL."
                })

        return rpc_err(request_id, -32601, f"Method not found: {method}")

    except Exception as e:
        return rpc_err(request_id, -32000, "ServerError", {"details": str(e)})
