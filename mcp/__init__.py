import azure.functions as func
import json
import os
import re
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

# ============================
# Configuration
# ============================

# MSI / IMDS
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"

# Resources for tokens
LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
ARM_RESOURCE = "https://management.azure.com/"

# Envs
WORKSPACE_ID_ENV = "WORKSPACE_ID"  # Log Analytics workspace *customer/workspace id* (GUID)
WORKSPACE_RESOURCE_ID_ENV = "WORKSPACE_RESOURCE_ID"  # Azure Resource ID of the Sentinel workspace

# Limits
MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50

# Timespan limits for Log Analytics query tool
MAX_HOURS = 24
DEFAULT_TIMESPAN = "PT1H"

# Log Analytics call hardening
LA_TIMEOUT_SECONDS = 60
LA_MAX_RETRIES_429 = 4
LA_BACKOFF_BASE_SECONDS = 2

# ARM call hardening
ARM_TIMEOUT_SECONDS = 30
ARM_MAX_RETRIES_429 = 4
ARM_BACKOFF_BASE_SECONDS = 2

# SecurityInsights API version (stable commonly used; update if you standardize on a different one)
SECURITYINSIGHTS_API_VERSION = os.environ.get("SECURITYINSIGHTS_API_VERSION", "2023-12-01-preview")


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

def normalize_timespan(ts: str) -> str:
    """
    Accepts ISO 8601 (PT1H, PT30M, P1D) and common shorthands (7d, 24h, 30m).
    Returns ISO 8601.
    """
    ts = (ts or "").strip()
    if not ts:
        return DEFAULT_TIMESPAN

    m = re.fullmatch(r"(\d+)\s*d", ts, re.IGNORECASE)
    if m:
        return f"P{m.group(1)}D"
    m = re.fullmatch(r"(\d+)\s*h", ts, re.IGNORECASE)
    if m:
        return f"PT{m.group(1)}H"
    m = re.fullmatch(r"(\d+)\s*m", ts, re.IGNORECASE)
    if m:
        return f"PT{m.group(1)}M"

    return ts

def parse_timespan_to_hours(timespan: str) -> float:
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan or "")
    if m:
        return int(m.group(1) or 0) + int(m.group(2) or 0) / 60.0
    d = re.fullmatch(r"P(\d+)D", timespan or "")
    if d:
        return int(d.group(1)) * 24.0
    raise ValueError("Invalid timespan format (use PT1H, PT30M, P1D, or shorthands like 7d/24h/30m).")

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

    # Adjust these to your comfort level
    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = (kql or "").lower()
    if " take " in lowered or " limit " in lowered or "|take" in lowered or "|limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

def get_required_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise ValueError(f"Missing required environment variable: {name}")
    return v


# ============================
# Managed Identity token
# ============================

def get_managed_identity_token(resource: str) -> str:
    """
    Works in Azure Functions/App Service with IDENTITY_ENDPOINT/HEADER and falls back to IMDS.
    """
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
# Log Analytics query (retry/backoff + timeout)
# ============================

def la_query(workspace_id: str, kql: str, timespan: str, token: str) -> Dict[str, Any]:
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {"query": kql, "timespan": timespan}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-ms-app": "sentinel-mcp-pro",
    }

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

            if e.code == 429 and attempt < LA_MAX_RETRIES_429 - 1:
                time.sleep(LA_BACKOFF_BASE_SECONDS * (2 ** attempt))
                continue

            # rethrow (caller will classify)
            raise urllib.error.HTTPError(e.url, e.code, e.msg, e.hdrs, None)  # avoid consumed body

        except Exception:
            raise

    raise RuntimeError("Log Analytics query failed after retries")


def parse_http_error_body(e: urllib.error.HTTPError) -> Dict[str, Any]:
    """
    Note: In la_query we re-raised HTTPError without body handle to avoid consumed stream.
    In this simplified version, you may not always have the body. Keep it defensive.
    """
    try:
        body_raw = e.read().decode("utf-8", errors="replace")
    except Exception:
        body_raw = ""
    try:
        body = json.loads(body_raw) if body_raw else {"raw": body_raw}
    except Exception:
        body = {"raw": body_raw}
    return {"status": e.code, "body": body, "message": str(e)}

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
        suggestions = ["Retry later (throttling).", "Reduce timespan.", "Reduce result size / simplify KQL."]
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
        suggestions = ["Check Managed Identity permissions on the workspace (Log Analytics Reader at minimum)."]
    elif status in (500, 502, 503, 504):
        error_type = "Transient"
        suggestions = ["Retry later.", "Reduce timespan/max_rows."]
    else:
        error_type = "HttpError"
        suggestions = ["Check query/table/columns and retry."]

    return {
        "error_type": error_type,
        "http_status": status,
        "message": msg or details.get("message") or "Log Analytics request failed",
        "suggestions": suggestions,
        "raw": body,
    }


# ============================
# ARM (SecurityInsights) calls for analytics rules
# ============================

def arm_request_json(url: str, token: str, method: str = "GET", payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-ms-app": "sentinel-mcp-pro",
    }

    data = json.dumps(payload).encode("utf-8") if payload is not None else None

    for attempt in range(ARM_MAX_RETRIES_429):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=ARM_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except urllib.error.HTTPError as e:
            # Best effort read body
            try:
                body_raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                body_raw = ""
            if e.code == 429 and attempt < ARM_MAX_RETRIES_429 - 1:
                time.sleep(ARM_BACKOFF_BASE_SECONDS * (2 ** attempt))
                continue
            raise urllib.error.HTTPError(e.url, e.code, body_raw or e.msg, e.hdrs, None)

    raise RuntimeError("ARM request failed after retries")


def get_workspace_resource_id() -> str:
    """
    Prefer a single env var:
      WORKSPACE_RESOURCE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/<wsName>
    """
    ws_rid = os.environ.get(WORKSPACE_RESOURCE_ID_ENV)
    if not ws_rid:
        raise ValueError(
            f"{WORKSPACE_RESOURCE_ID_ENV} not configured. "
            "Set it to the Log Analytics workspace Azure resource ID."
        )
    return ws_rid.rstrip("/")


def build_alert_rules_url(workspace_resource_id: str) -> str:
    return (
        f"{workspace_resource_id}/providers/Microsoft.SecurityInsights/alertRules"
        f"?api-version={SECURITYINSIGHTS_API_VERSION}"
    )

def build_alert_rule_get_url(workspace_resource_id: str, rule_id: str) -> str:
    rule_id = (rule_id or "").strip()
    if not rule_id:
        raise ValueError("Missing 'rule_id'")
    # rule_id can be either GUID/name or full ARM id. Support both.
    if rule_id.lower().startswith("/subscriptions/"):
        # full id provided
        if "api-version=" in rule_id.lower():
            return rule_id
        return f"{rule_id}?api-version={SECURITYINSIGHTS_API_VERSION}"
    return (
        f"{workspace_resource_id}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
        f"?api-version={SECURITYINSIGHTS_API_VERSION}"
    )

def summarize_rules(values: List[Dict[str, Any]], max_items: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for v in values[:max_items]:
        props = v.get("properties", {}) if isinstance(v, dict) else {}
        out.append({
            "id": v.get("id"),
            "name": v.get("name"),
            "displayName": props.get("displayName"),
            "kind": v.get("kind"),
            "enabled": props.get("enabled"),
            "severity": props.get("severity"),
            "tactics": props.get("tactics"),
            "techniques": props.get("techniques"),
        })
    return out


# ============================
# Tools (Log Analytics)
# ============================

def tool_run_query(workspace_id: str, token: str, kql: str, timespan: str, max_rows: int) -> Dict[str, Any]:
    if not kql:
        raise ValueError("Missing 'kql'")

    timespan = normalize_timespan(timespan)
    kql_safety_check(kql)

    hours = parse_timespan_to_hours(timespan)
    if hours <= 0 or hours > MAX_HOURS:
        raise ValueError(f"timespan exceeds allowed window ({MAX_HOURS}h). Use smaller timespan.")

    kql = ensure_take_limit(kql, max_rows)
    data = la_query(workspace_id, kql, timespan, token)
    return {"meta": {"timespan": timespan, "max_rows": max_rows}, "data": data}

def tool_list_tables(workspace_id: str, token: str, timespan: str) -> Dict[str, Any]:
    timespan = normalize_timespan(timespan)
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
    timespan = normalize_timespan(timespan)
    kql = f"{table} | getschema"
    data = la_query(workspace_id, kql, timespan, token)
    return {"meta": {"table": table, "timespan": timespan}, "data": data}

def tool_preview_table(workspace_id: str, token: str, table: str, timespan: str, take_rows: int) -> Dict[str, Any]:
    if not table:
        raise ValueError("Missing 'table'")
    timespan = normalize_timespan(timespan)
    take_rows = max(1, min(int(take_rows or 10), 50))
    kql = f"{table} | take {take_rows}"
    data = la_query(workspace_id, kql, timespan, token)
    return {"meta": {"table": table, "timespan": timespan, "take": take_rows}, "data": data}


# ============================
# Tools (Sentinel Analytics Rules via ARM)
# ============================

def tool_list_analytic_rules(arm_token: str, max_items: int) -> Dict[str, Any]:
    max_items = max(1, min(int(max_items or 50), 200))
    ws_rid = get_workspace_resource_id()
    url = build_alert_rules_url(ws_rid)

    data = arm_request_json(url, arm_token, method="GET")
    values = data.get("value", []) if isinstance(data, dict) else []

    return {
        "meta": {
            "workspace_resource_id": ws_rid,
            "api_version": SECURITYINSIGHTS_API_VERSION,
            "returned": min(len(values), max_items),
            "total_in_page": len(values),
            "note": "If you have more than one page of rules, add paging support (nextLink).",
        },
        "rules": summarize_rules(values, max_items),
        "raw": {"has_nextLink": bool(data.get("nextLink"))},
    }

def tool_get_analytic_rule(arm_token: str, rule_id: str) -> Dict[str, Any]:
    ws_rid = get_workspace_resource_id()
    url = build_alert_rule_get_url(ws_rid, rule_id)
    data = arm_request_json(url, arm_token, method="GET")
    props = data.get("properties", {}) if isinstance(data, dict) else {}

    return {
        "meta": {
            "workspace_resource_id": ws_rid,
            "api_version": SECURITYINSIGHTS_API_VERSION,
        },
        "rule": {
            "id": data.get("id"),
            "name": data.get("name"),
            "kind": data.get("kind"),
            "displayName": props.get("displayName"),
            "enabled": props.get("enabled"),
            "severity": props.get("severity"),
            "description": props.get("description"),
            "tactics": props.get("tactics"),
            "techniques": props.get("techniques"),
            "query": props.get("query"),  # present for Scheduled rules
            "queryFrequency": props.get("queryFrequency"),
            "queryPeriod": props.get("queryPeriod"),
            "triggerOperator": props.get("triggerOperator"),
            "triggerThreshold": props.get("triggerThreshold"),
        },
        "raw": data,
    }

def tool_get_analytic_rule_kql(arm_token: str, rule_id: str) -> Dict[str, Any]:
    rule = tool_get_analytic_rule(arm_token, rule_id)
    props_query = (((rule or {}).get("rule") or {}).get("query"))

    if not props_query:
        kind = (((rule or {}).get("rule") or {}).get("kind"))
        return {
            "meta": rule.get("meta"),
            "rule_id": rule_id,
            "found_query": False,
            "message": (
                "No 'properties.query' found. This rule may not be a Scheduled analytic rule "
                f"(kind={kind}), or query isn't exposed in this object."
            ),
            "rule_summary": {
                k: rule["rule"].get(k) for k in ["id", "name", "kind", "displayName", "enabled", "severity"]
            },
        }

    return {
        "meta": rule.get("meta"),
        "rule_id": rule_id,
        "found_query": True,
        "kql": props_query,
        "rule_summary": {
            k: rule["rule"].get(k) for k in ["id", "name", "kind", "displayName", "enabled", "severity"]
        },
    }


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
                "serverInfo": {"name": "sentinel-mcp-pro", "version": "1.1.0"}
            })

        # tools/list
        if method == "tools/list":
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
                    },
                    # NEW: Sentinel Analytics Rules tools (ARM / SecurityInsights)
                    {
                        "name": "list_analytic_rules",
                        "description": "List Sentinel analytics rules (Microsoft.SecurityInsights/alertRules)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "max_items": {"type": "integer"}
                            }
                        }
                    },
                    {
                        "name": "get_analytic_rule",
                        "description": "Get a Sentinel analytics rule object by rule_id (GUID/name or full ARM id)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "rule_id": {"type": "string"}
                            },
                            "required": ["rule_id"]
                        }
                    },
                    {
                        "name": "get_analytic_rule_kql",
                        "description": "Get the KQL (properties.query) for a Scheduled analytics rule by rule_id",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "rule_id": {"type": "string"}
                            },
                            "required": ["rule_id"]
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

            # Only require WORKSPACE_ID for Log Analytics tools; ARM tools can work with only WORKSPACE_RESOURCE_ID
            la_tools = {"run_query", "list_tables", "get_table_schema", "preview_table"}
            arm_tools = {"list_analytic_rules", "get_analytic_rule", "get_analytic_rule_kql"}

            try:
                if tool_name in la_tools:
                    if not workspace_id:
                        return rpc_err(request_id, -32000, f"{WORKSPACE_ID_ENV} not configured")
                    la_token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

                    if tool_name == "run_query":
                        result = tool_run_query(
                            workspace_id,
                            la_token,
                            args.get("kql"),
                            args.get("timespan", DEFAULT_TIMESPAN),
                            clamp_rows(args.get("max_rows", DEFAULT_ROWS))
                        )
                    elif tool_name == "list_tables":
                        result = tool_list_tables(
                            workspace_id,
                            la_token,
                            args.get("timespan", DEFAULT_TIMESPAN)
                        )
                    elif tool_name == "get_table_schema":
                        result = tool_get_table_schema(
                            workspace_id,
                            la_token,
                            args.get("table"),
                            args.get("timespan", DEFAULT_TIMESPAN)
                        )
                    elif tool_name == "preview_table":
                        result = tool_preview_table(
                            workspace_id,
                            la_token,
                            args.get("table"),
                            args.get("timespan", DEFAULT_TIMESPAN),
                            args.get("take", 10)
                        )
                    else:
                        return rpc_err(request_id, -32601, f"Tool not found: {tool_name}")

                elif tool_name in arm_tools:
                    arm_token = get_managed_identity_token(ARM_RESOURCE)

                    if tool_name == "list_analytic_rules":
                        result = tool_list_analytic_rules(
                            arm_token,
                            args.get("max_items", 50)
                        )
                    elif tool_name == "get_analytic_rule":
                        result = tool_get_analytic_rule(
                            arm_token,
                            args.get("rule_id")
                        )
                    elif tool_name == "get_analytic_rule_kql":
                        result = tool_get_analytic_rule_kql(
                            arm_token,
                            args.get("rule_id")
                        )
                    else:
                        return rpc_err(request_id, -32601, f"Tool not found: {tool_name}")

                else:
                    return rpc_err(request_id, -32601, f"Tool not found: {tool_name}")

                # IMPORTANT: only 'text' blocks for .NET MCP client
                return rpc_ok(request_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(result, ensure_ascii=False, indent=2)
                    }]
                })

            except ValueError as e:
                # Make param/validation errors explicit for the client
                return rpc_err(request_id, -32602, str(e), {
                    "error_type": "InvalidParams",
                    "hint": "Check required args/env vars and try again."
                })

            except urllib.error.HTTPError as e:
                # Try to classify LA errors; ARM errors will still be useful via status/body
                details = parse_http_error_body(e)
                classified = classify_la_error(details)
                # If it's not actually LA, this still returns something sensible.
                return rpc_err(request_id, -32000, classified.get("message", "HTTP error"), classified)

            except Exception as e:
                return rpc_err(request_id, -32000, "Unhandled server exception", {
                    "details": str(e),
                    "hint": "If this happened on a heavy query, reduce timespan or simplify inputs. For analytics rules, confirm WORKSPACE_RESOURCE_ID + MI permissions."
                })

        return rpc_err(request_id, -32601, f"Method not found: {method}")

    except Exception as e:
        return rpc_err(request_id, -32000, "ServerError", {"details": str(e)})
