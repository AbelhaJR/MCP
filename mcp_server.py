from fastmcp import FastMCP
import requests
import os
import re
import json
import urllib.request
import time
from typing import Any, Dict, List, Optional

# ============================
# MCP Setup
# ============================

mcp = FastMCP("SentinelMCP")

SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
WORKSPACE_NAME = os.environ.get("WORKSPACE_NAME")
# ============================
# Configuration
# ============================

LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"

WORKSPACE_ID = os.environ.get("WORKSPACE_ID")

MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50

# Keep run_query bounded (Teams-friendly + safety)
MAX_HOURS_RUN_QUERY = 24

# For listing tables, P1D is the most intuitive default
DEFAULT_TIMESPAN = os.environ.get("DEFAULT_TIMESPAN", "P1D")

# Lower timeout to avoid Teams/M365 action timeouts masking the real error
HTTP_TIMEOUT_SECONDS = int(os.environ.get("LA_HTTP_TIMEOUT", "15"))

# ============================
# Managed Identity
# ============================

# Cache token briefly to avoid repeated MSI calls in short bursts
_TOKEN_CACHE: Dict[str, Any] = {"token": None, "exp": 0}

def get_managed_identity_token(resource: str) -> str:
    now = int(time.time())
    cached = _TOKEN_CACHE.get("token")
    exp = int(_TOKEN_CACHE.get("exp") or 0)
    if cached and exp - now > 60:
        return cached

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
            payload = json.loads(resp.read().decode())
            token = payload["access_token"]
            expires_in = int(payload.get("expires_in") or 300)
            _TOKEN_CACHE["token"] = token
            _TOKEN_CACHE["exp"] = now + expires_in
            return token

    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")

    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
        token = payload["access_token"]
        expires_in = int(payload.get("expires_in") or 300)
        _TOKEN_CACHE["token"] = token
        _TOKEN_CACHE["exp"] = now + expires_in
        return token

# ============================
# Guardrails
# ============================

def parse_timespan_to_hours(timespan: str) -> float:
    """
    Supports:
      - PT#H
      - PT#M
      - PT#H#M
      - P#D
    """
    ts = (timespan or "").strip()
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", ts)
    if m:
        h = int(m.group(1) or 0)
        mins = int(m.group(2) or 0)
        total = h + mins / 60.0
        if total <= 0:
            raise ValueError("Timespan must be > 0")
        return total

    d = re.fullmatch(r"P(\d+)D", ts)
    if d:
        days = int(d.group(1))
        if days <= 0:
            raise ValueError("Timespan must be > 0")
        return days * 24.0

    raise ValueError("Invalid timespan format. Use PT1H, PT6H, PT24H or P1D, P7D.")

def clamp_rows(n: Any) -> int:
    try:
        v = int(n)
    except Exception:
        v = DEFAULT_ROWS
    return max(1, min(v, MAX_ROWS_HARD))

def kql_safety_check(kql: str):
    lowered = (kql or "").lower()

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' not allowed")

    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = (kql or "").lower()
    if "| take" in lowered or "| limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

# ============================
# Log Analytics Query
# ============================

def _ok(data: Any, **meta) -> dict:
    out = {"ok": True, "data": data}
    if meta:
        out["meta"] = meta
    return out

def _fail(message: str, *, status_code: Optional[int] = None, detail: Optional[str] = None, **meta) -> dict:
    out = {"ok": False, "error": {"message": message}}
    if status_code is not None:
        out["error"]["status_code"] = status_code
    if detail:
        out["error"]["detail"] = detail
    if meta:
        out["meta"] = meta
    return out

def la_query(kql: str, timespan: str) -> dict:
    if not WORKSPACE_ID:
        return _fail("WORKSPACE_ID not configured on the Function App")

    try:
        token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)
    except Exception as e:
        return _fail("Failed to acquire Managed Identity token", detail=str(e))

    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"

    try:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "query": kql,
                "timespan": timespan,
            },
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except Exception as e:
        return _fail("HTTP request to Log Analytics failed", detail=str(e), timespan=timespan)

    if not response.ok:
        # IMPORTANT: do NOT return {"error": True, ...} — some runtimes treat that as tool failure
        return _fail(
            "Log Analytics query failed",
            status_code=response.status_code,
            detail=response.text,
            timespan=timespan,
        )

    try:
        return _ok(response.json(), timespan=timespan)
    except Exception as e:
        return _fail("Failed to parse Log Analytics JSON response", detail=str(e), timespan=timespan)

# ============================
# Entity Detection
# ============================

def escape_kql_string(s: str) -> str:
    return (s or "").replace('"', '""')

def detect_entity_type(value: str) -> str:
    v = (value or "").strip()

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        return "ip"

    if "@" in v:
        return "user"

    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"

    if "." in v:
        return "domain"

    return "generic"
# ============================
# Tool inventory (do NOT rely on LLM memory)
# ============================

_TOOL_DEFS: List[dict] = [
    {
        "name": "get_tools",
        "description": "Returns the exact MCP tool list and parameter formats. Use this when asked what tools are available.",
        "params": {},
    },
    {
        "name": "ping",
        "description": "Connectivity test for the MCP endpoint (does not query Sentinel). Use before data operations if needed.",
        "params": {},
    },
    {
        "name": "list_tables",
        "description": "Lists tables that ingested data within the given timespan (uses the Usage table).",
        "params": {"timespan": "ISO8601 duration like P1D, PT6H, PT24H"},
    },
    {
        "name": "preview_table",
        "description": "Shows a small preview (10 rows) from the specified table.",
        "params": {"table": "Table name string"},
    },
    {
        "name": "get_table_schema",
        "description": "Retrieves the schema (columns and types) for the specified table.",
        "params": {"table": "Table name string"},
    },
    {
        "name": "run_query",
        "description": "Runs a bounded KQL query for the given timespan and returns up to max_rows rows.",
        "params": {"kql": "KQL string", "timespan": "ISO8601 duration", "max_rows": "integer <= 200"},
    },
    {"name": "analyze_entity",
     "description": "SOC-style entity analysis across common Sentinel tables",
     "params": {"value": "Entity string", "timespan": "ISO8601 duration", "max_rows": "integer <= 200"}}
]

@mcp.tool
def get_tools() -> dict:
    """Return the exact MCP tool list (source of truth)."""
    return _ok({"tools": _TOOL_DEFS, "mcp_path": "/mcp"})

@mcp.tool
def ping() -> dict:
    """Simple health check that doesn't touch Sentinel."""
    return _ok(
        {
            "message": "pong",
            "workspace_configured": bool(WORKSPACE_ID),
            "mcp_path": "/mcp",
        }
    )

# ============================
# Tools
# ============================
@mcp.tool
def analyze_entity(value: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:

    if not value:
        return _fail("value is required")

    hours = parse_timespan_to_hours(timespan)
    if hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)")

    entity_type = detect_entity_type(value)
    safe_value = escape_kql_string(value)
    max_rows = clamp_rows(max_rows)

    table_map = {
        "ip": [
            ("SigninLogs", f'IPAddress == "{safe_value}"'),
            ("SecurityEvent", f'IpAddress == "{safe_value}"'),
            ("AzureActivity", f'CallerIpAddress == "{safe_value}"'),
        ],
        "user": [
            ("SigninLogs", f'UserPrincipalName =~ "{safe_value}"'),
            ("SecurityEvent", f'Account =~ "{safe_value}"'),
            ("AuditLogs", f'tostring(InitiatedBy.user.userPrincipalName) =~ "{safe_value}"'),
        ],
        "domain": [
            ("DeviceNetworkEvents", f'RemoteUrl contains "{safe_value}"'),
        ],
        "generic": [
            ("SigninLogs", f'tostring(*) contains "{safe_value}"'),
        ]
    }

    queries = table_map.get(entity_type, table_map["generic"])

    report = []

    for table, where_clause in queries:
        kql = f"""
        {table}
        | where {where_clause}
        | summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
        """

        res = la_query(kql, timespan)
        if not res.get("ok"):
            continue

        tables = res["data"].get("tables") or []
        if not tables or not tables[0].get("rows"):
            continue

        row = tables[0]["rows"][0]
        if row[0] == 0:
            continue

        report.append({
            "table": table,
            "count": row[0],
            "first_seen": row[1],
            "last_seen": row[2]
        })

    return _ok({
        "entity": value,
        "entity_type": entity_type,
        "timespan": timespan,
        "results": report
    })

@mcp.tool
def list_tables(timespan: str = DEFAULT_TIMESPAN) -> dict:
    """
    List tables that ingested data within the given timespan.
    Uses the Usage table (most reliable method).
    """
    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", detail=str(e))

    kql = """
Usage
| where Quantity > 0
| summarize Count=sum(Quantity) by DataType
| order by Count desc
| take 50
""".strip()

    res = la_query(kql, timespan)
    if not res.get("ok"):
        return res

    payload = res["data"]
    tables = payload.get("tables") or []
    if not tables:
        return _fail("No tables returned from Log Analytics", timespan=timespan)

    t0 = tables[0]
    columns = [c.get("name") for c in (t0.get("columns") or [])]
    rows = t0.get("rows") or []

    if "DataType" not in columns:
        return _fail("Unexpected response shape: DataType column not present", timespan=timespan)

    idx = columns.index("DataType")
    return _ok({"tables": [row[idx] for row in rows]}, timespan=timespan)

@mcp.tool
def preview_table(table: str) -> dict:
    """Preview 10 rows from a table."""
    if not table or not isinstance(table, str):
        return _fail("Table name is required")
    kql = f"{table} | take 10"
    return la_query(kql, DEFAULT_TIMESPAN)

@mcp.tool
def get_table_schema(table: str) -> dict:
    """Get schema of a table."""
    if not table or not isinstance(table, str):
        return _fail("Table name is required")
    kql = f"{table} | getschema"
    return la_query(kql, DEFAULT_TIMESPAN)

@mcp.tool
def run_query(kql: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    """
    Run a bounded KQL query (max 24h timespan).
    """
    if not kql or not isinstance(kql, str):
        return _fail("kql is required")

    try:
        kql_safety_check(kql)
    except Exception as e:
        return _fail("KQL rejected by safety policy", detail=str(e))

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_RUN_QUERY:
        return _fail(f"Timespan exceeds allowed window ({MAX_HOURS_RUN_QUERY}h max)", detail=f"got {hours}h")

    kql = ensure_take_limit(kql, clamp_rows(max_rows))
    return la_query(kql, timespan)
# ============================
# Advanced SOC Entity Analysis Tool
# ============================
# ============================
# Sentinel Analytics Rule (Use Case) Documentation Tools
# ============================

ARM_RESOURCE = "https://management.azure.com/"

def _extract_tables_from_kql(kql: str) -> List[str]:
    if not kql:
        return []
    candidates = re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\s*\|", kql)
    seen = set()
    out = []
    for t in candidates:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _extract_ops_from_kql(kql: str) -> List[str]:
    if not kql:
        return []
    ops = [
        "where", "summarize", "join", "extend",
        "project", "project-away", "parse",
        "mv-expand", "evaluate", "union",
        "lookup", "distinct"
    ]
    lowered = kql.lower()
    return [op for op in ops if re.search(rf"\b{re.escape(op)}\b", lowered)]


def _extract_threshold_snippets(kql: str) -> List[str]:
    if not kql:
        return []
    matches = re.findall(
        r"(?i)\bwhere\b[^\n]{0,140}?(?:>=|<=|==|!=|>|<)\s*\d+(?:\.\d+)?",
        kql,
    )
    seen = set()
    out = []
    for m in matches:
        m2 = " ".join(m.split())
        if m2 not in seen:
            seen.add(m2)
            out.append(m2)
        if len(out) >= 10:
            break
    return out


def _detect_entity_hints(kql: str) -> List[str]:
    if not kql:
        return []
    fields = [
        "UserPrincipalName", "Account", "AccountName", "AadUserId",
        "IPAddress", "IpAddress", "CallerIpAddress", "RemoteIP",
        "DeviceName", "Computer", "HostName",
        "FileName", "SHA256", "SHA1", "MD5",
        "ProcessCommandLine", "CommandLine", "Url", "RemoteUrl"
    ]
    hits = []
    for f in fields:
        if re.search(rf"\b{re.escape(f)}\b", kql, re.IGNORECASE):
            hits.append(f)
    return hits[:20]


def _kql_one_liner_summary(kql: str) -> str:
    if not kql:
        return ""
    lines = [ln.strip() for ln in kql.splitlines() if ln.strip()]
    head = lines[0] if lines else ""
    ops = _extract_ops_from_kql(kql)
    if ops:
        return f"{head} (ops: {', '.join(ops[:8])})"
    return head
    
def _arm_get(url: str) -> dict:
    try:
        token = get_managed_identity_token(ARM_RESOURCE)
    except Exception as e:
        return _fail("Failed to acquire ARM token", detail=str(e))

    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except Exception as e:
        return _fail("HTTP request to ARM failed", detail=str(e))

    if not resp.ok:
        return _fail("ARM request failed", status_code=resp.status_code, detail=resp.text)

    try:
        return _ok(resp.json())
    except Exception as e:
        return _fail("Failed to parse ARM JSON response", detail=str(e))


def _sentinel_rules_base_url() -> str:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        raise ValueError("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured")

    return (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )


# ---- Add tools to inventory (ENV version) ----
_TOOL_DEFS.append(
    {
        "name": "list_analytics_rules",
        "description": "Lists Microsoft Sentinel analytics rules in the configured workspace.",
        "params": {
            "top": "optional int; max rules to return (default 50, hard cap 200)"
        },
    }
)

_TOOL_DEFS.append(
    {
        "name": "analyze_use_case",
        "description": "Fetch Sentinel analytic rule by rule_id or rule_name and extract documentation-ready key points.",
        "params": {
            "rule_id": "optional: analytic rule ARM resource name/guid",
            "rule_name": "optional: displayName match (case-insensitive exact match preferred)",
        },
    }
)


@mcp.tool
def list_analytics_rules(top: int = 50) -> dict:

    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured")

    try:
        top_i = int(top)
    except Exception:
        top_i = 50
    top_i = max(1, min(top_i, 200))

    base = _sentinel_rules_base_url()
    url = f"{base}?api-version=2023-09-01-preview"

    res = _arm_get(url)
    if not res.get("ok"):
        return res

    items = res["data"].get("value") or []

    out = []
    for it in items[:top_i]:
        props = it.get("properties") or {}
        out.append({
            "rule_id": it.get("name"),
            "display_name": props.get("displayName"),
            "kind": it.get("kind"),
            "enabled": props.get("enabled"),
            "severity": props.get("severity"),
        })

    return _ok({"count": len(out), "rules": out})


def _fetch_rule_by_id(rule_id: str) -> dict:
    base = _sentinel_rules_base_url()
    url = f"{base}/{rule_id}?api-version=2023-09-01-preview"
    return _arm_get(url)


def _find_rule_id_by_name(rule_name: str) -> Optional[str]:
    base = _sentinel_rules_base_url()
    url = f"{base}?api-version=2023-09-01-preview"

    res = _arm_get(url)
    if not res.get("ok"):
        return None

    target = (rule_name or "").strip().lower()

    for it in (res["data"].get("value") or []):
        props = it.get("properties") or {}
        dn = (props.get("displayName") or "").strip().lower()
        if dn == target:
            return it.get("name")

    return None


@mcp.tool
def analyze_use_case(
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
) -> dict:

    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured")

    rid = (rule_id or "").strip()
    rname = (rule_name or "").strip()

    if not rid and not rname:
        return _fail("Provide rule_id or rule_name")

    if not rid and rname:
        rid = _find_rule_id_by_name(rname) or ""
        if not rid:
            return _fail("Rule not found by name", detail="Try list_analytics_rules")

    res = _fetch_rule_by_id(rid)
    if not res.get("ok"):
        return res

    rule = res["data"] or {}
    props = rule.get("properties") or {}

    kql = props.get("query") or ""
    tables = _extract_tables_from_kql(kql)
    ops = _extract_ops_from_kql(kql)
    thresholds = _extract_threshold_snippets(kql)
    entities = _detect_entity_hints(kql)

    doc = {
        "rule_id": rule.get("name"),
        "rule_display_name": props.get("displayName"),
        "description": props.get("description"),
        "severity": props.get("severity"),
        "enabled": props.get("enabled"),
        "kind": rule.get("kind"),
        "mitre_tactics": props.get("tactics") or [],
        "mitre_techniques": props.get("techniques") or [],
        "schedule": {
            "query_frequency": props.get("queryFrequency"),
            "query_period": props.get("queryPeriod"),
        },
        "trigger": {
            "operator": props.get("triggerOperator"),
            "threshold": props.get("triggerThreshold"),
        },
        "kql": {
            "query": kql[:12000],
            "summary": _kql_one_liner_summary(kql),
            "tables_used": tables[:25],
            "operators_used": ops,
            "threshold_hints": thresholds,
            "entity_field_hints": entities,
        },
    }

    return _ok(doc)
# ============================
# Export ASGI App (IMPORTANT)
# ============================

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
