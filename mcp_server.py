from fastmcp import FastMCP
import requests
import os
import re
import json
import urllib.request
import time
from typing import Any, Dict, List, Optional, Tuple

# ============================================================
# MCP SETUP
# ============================================================

mcp = FastMCP("SentinelMCP")

# ============================================================
# PATHS / CATALOG
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TABLE_CATALOG_PATH = os.path.join(BASE_DIR, "workspace_tables.json")

WORKSPACE_TABLE_CATALOG: Dict[str, List[str]] = {}

try:
    with open(TABLE_CATALOG_PATH, "r", encoding="utf-8") as f:
        raw_catalog = json.load(f)
        if isinstance(raw_catalog, dict):
            WORKSPACE_TABLE_CATALOG = {
                str(k): [str(v) for v in vals if isinstance(v, str)]
                for k, vals in raw_catalog.items()
                if isinstance(vals, list)
            }
        else:
            print("Workspace catalog is not a JSON object")
except Exception as e:
    print("Failed to load workspace catalog:", e)
    WORKSPACE_TABLE_CATALOG = {}

# ============================================================
# CONFIGURATION
# ============================================================

SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
WORKSPACE_NAME = os.environ.get("WORKSPACE_NAME")
WORKSPACE_ID = os.environ.get("WORKSPACE_ID")

LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
ARM_RESOURCE = "https://management.azure.com/"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"

MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50

DEFAULT_TIMESPAN = os.environ.get("DEFAULT_TIMESPAN", "P3D")
HTTP_TIMEOUT_SECONDS = int(os.environ.get("LA_HTTP_TIMEOUT", "15"))

MAX_HOURS_RUN_QUERY = 72
MAX_HOURS_ANALYZE_ENTITY = 168
MAX_HOURS_INCIDENT = 168

# ============================================================
# RESPONSE HELPERS
# ============================================================

def _ok(data: Any, **meta) -> dict:
    out = {"ok": True, "data": data}
    if meta:
        out["meta"] = meta
    return out

def _fail(
    message: str,
    *,
    code: Optional[str] = None,
    status_code: Optional[int] = None,
    detail: Optional[str] = None,
    **meta,
) -> dict:
    out = {"ok": False, "error": {"message": message}}
    if code:
        out["error"]["code"] = code
    if status_code is not None:
        out["error"]["status_code"] = status_code
    if detail:
        out["error"]["detail"] = detail
    if meta:
        out["meta"] = meta
    return out

# ============================================================
# TOOL INVENTORY
# ============================================================

_TOOL_DEFS: List[dict] = []

def _register_tool_def(name: str, description: str, params: dict) -> None:
    _TOOL_DEFS.append(
        {
            "name": name,
            "description": description,
            "params": params,
        }
    )

# ============================================================
# MANAGED IDENTITY
# ============================================================

_TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}

def get_managed_identity_token(resource: str) -> str:
    now = int(time.time())

    cached = _TOKEN_CACHE.get(resource)
    if cached and cached.get("exp", 0) - now > 60:
        return cached["token"]

    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER") or os.environ.get("MSI_SECRET")
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")

    # App Service / Function App managed identity endpoint
    if identity_endpoint and identity_header:
        sep = "&" if "?" in identity_endpoint else "?"
        extra = f"&client_id={client_id}" if client_id else ""
        url = f"{identity_endpoint}{sep}resource={resource}&api-version=2019-08-01{extra}"

        req = urllib.request.Request(
            url,
            headers={
                "X-IDENTITY-HEADER": identity_header,
                "Metadata": "true",
            },
            method="GET",
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode())
            token = payload["access_token"]
            expires_in = int(payload.get("expires_in") or 300)

            _TOKEN_CACHE[resource] = {
                "token": token,
                "exp": now + expires_in,
            }
            return token

    # Fallback IMDS
    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(
        url,
        headers={"Metadata": "true"},
        method="GET",
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
        token = payload["access_token"]
        expires_in = int(payload.get("expires_in") or 300)

        _TOKEN_CACHE[resource] = {
            "token": token,
            "exp": now + expires_in,
        }
        return token

# ============================================================
# GUARDRAILS / HELPERS
# ============================================================

_TABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

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

def escape_kql_string(s: str) -> str:
    return (s or "").replace('"', '""')

def validate_table_name(table: str) -> str:
    if not table or not isinstance(table, str):
        raise ValueError("Table name is required")
    table = table.strip()
    if not _TABLE_RE.fullmatch(table):
        raise ValueError("Invalid table name")
    return table

def kql_safety_check(kql: str):
    lowered = (kql or "").lower()

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' not allowed")

    blocked = [
        "externaldata",
        "evaluate",
        "make-series",
        ".drop",
        ".delete",
        ".alter",
        ".create",
        ".ingest",
    ]

    for op in blocked:
        if op in lowered:
            raise ValueError(f"KQL contains blocked operator: {op}")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = (kql or "").lower()
    if "| take" in lowered or "| limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

def detect_entity_type(value: str) -> str:
    v = (value or "").strip()

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        try:
            parts = [int(x) for x in v.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return "ip"
        except Exception:
            pass

    if "@" in v:
        return "user"

    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"

    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"

    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"

    if "." in v:
        return "domain"

    return "host"

def _la_first_table_rows(payload: dict) -> Tuple[List[str], List[List[Any]]]:
    tables = payload.get("tables") or []
    if not tables:
        return [], []
    t0 = tables[0]
    columns = [c.get("name") for c in (t0.get("columns") or [])]
    rows = t0.get("rows") or []
    return columns, rows

def _la_first_table_dicts(payload: dict) -> List[dict]:
    columns, rows = _la_first_table_rows(payload)
    return [dict(zip(columns, r)) for r in rows]

def _flatten_catalog_tables() -> List[str]:
    seen = set()
    out = []
    for tables in WORKSPACE_TABLE_CATALOG.values():
        for t in tables:
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out

def _catalog_domains_for_entity(entity_type: str) -> List[str]:
    mapping = {
        "ip": [
            "alerts_and_incidents",
            "identity_and_authentication",
            "endpoint_microsoft_defender",
            "network_security_devices",
            "network_and_proxy",
            "cmdb_and_asset_context",
        ],
        "user": [
            "alerts_and_incidents",
            "identity_and_authentication",
            "endpoint_microsoft_defender",
            "email_and_m365",
            "identity_governance_and_pam",
        ],
        "host": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "windows_servers",
            "linux_servers",
            "cmdb_and_asset_context",
        ],
        "domain": [
            "alerts_and_incidents",
            "network_and_proxy",
            "dns_and_ip_management",
            "email_and_m365",
        ],
        "sha256": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "security_and_behavior_analytics",
        ],
        "sha1": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "security_and_behavior_analytics",
        ],
        "md5": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "security_and_behavior_analytics",
        ],
    }
    preferred = mapping.get(entity_type, ["alerts_and_incidents", "identity_and_authentication"])
    return [d for d in preferred if d in WORKSPACE_TABLE_CATALOG]

def _catalog_tables_for_domains(domains: List[str]) -> List[str]:
    seen = set()
    out = []
    for domain in domains:
        for table in WORKSPACE_TABLE_CATALOG.get(domain, []):
            if table not in seen:
                seen.add(table)
                out.append(table)
    return out

CMDB_TABLE = "COVERAGE_CMDB"

def _query_cmdb_entity(value: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    safe_value = escape_kql_string(value)

    kql = f"""
{CMDB_TABLE}
| where
    tostring(Key) contains "{safe_value}"
    or tostring(Management_IP) contains "{safe_value}"
    or tostring(ApplicationAndComponentInstance) contains "{safe_value}"
    or tostring(Network_Interfaces) contains "{safe_value}"
    or tostring(BusinessEntity) contains "{safe_value}"
    or tostring(FQDN) contains "{safe_value}"
    or tostring(PSNC) contains "{safe_value}"
    or tostring(Scanning_Information) contains "{safe_value}"
| project
    Key,
    Management_IP,
    ApplicationAndComponentInstance,
    Network_Interfaces,
    Updated,
    Scanning_Information,
    BusinessEntity,
    FQDN,
    PSNC
| take 20
""".strip()

    return la_query(kql, timespan)
# ============================================================
# LOG ANALYTICS / ARM CLIENTS
# ============================================================

def la_query(kql: str, timespan: str) -> dict:
    if not WORKSPACE_ID:
        return _fail("WORKSPACE_ID not configured on the Function App", code="CONFIG_ERROR")

    try:
        token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)
    except Exception as e:
        return _fail(
            "Failed to acquire Managed Identity token",
            code="MANAGED_IDENTITY_ERROR",
            detail=str(e),
        )

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
        return _fail(
            "HTTP request to Log Analytics failed",
            code="HTTP_ERROR",
            detail=str(e),
            timespan=timespan,
        )

    if not response.ok:
        return _fail(
            "Log Analytics query failed",
            code="LOG_ANALYTICS_ERROR",
            status_code=response.status_code,
            detail=response.text,
            timespan=timespan,
        )

    try:
        return _ok(response.json(), timespan=timespan)
    except Exception as e:
        return _fail(
            "Failed to parse Log Analytics JSON response",
            code="PARSE_ERROR",
            detail=str(e),
            timespan=timespan,
        )

def _arm_get(url: str) -> dict:
    try:
        token = get_managed_identity_token(ARM_RESOURCE)
    except Exception as e:
        return _fail("Failed to acquire ARM token", code="MANAGED_IDENTITY_ERROR", detail=str(e))

    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except Exception as e:
        return _fail("HTTP request to ARM failed", code="HTTP_ERROR", detail=str(e))

    if not resp.ok:
        return _fail(
            "ARM request failed",
            code="ARM_ERROR",
            status_code=resp.status_code,
            detail=resp.text,
        )

    try:
        return _ok(resp.json())
    except Exception as e:
        return _fail("Failed to parse ARM JSON response", code="PARSE_ERROR", detail=str(e))

# ============================================================
# ANALYTICS RULE HELPERS
# ============================================================

CONFLUENCE_TEMPLATE = """
<p><strong>TYPE:</strong> USE CASE - <strong>SEVERITY:</strong> {severity}</p>
<hr/>

<h1>USE CASE SUMMARY</h1>
<p><strong>Purpose</strong></p>
<p>The purpose of this document is to describe the detection logic and implementation of the use case <strong>{rule_name}</strong>.</p>

<hr/>

<h1>Threat Layer</h1>

<h2>MITRE ATT&CK</h2>
<table>
<tr><th>Tactic</th><th>Technique</th></tr>
{mitre_rows}
</table>

<h2>Cyber Kill Chain</h2>
<p>The use case primarily addresses the following phase:</p>
<p><strong>{kill_chain_phase}</strong></p>

<h2>References</h2>
<ul>
<li>Microsoft Sentinel analytic rule: {rule_name}</li>
</ul>

<hr/>

<h1>Implementation Layer</h1>

<h2>Log Sources</h2>
<p>{tables}</p>

<h2>Scope</h2>
<p>This rule runs every {query_frequency} with a lookback of {query_period}.</p>

<h2>Monitoring Rules</h2>
<pre>{kql}</pre>

<h2>Entities</h2>
<ul>
{entities}
</ul>
"""

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

def _sentinel_rules_base_url() -> str:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        raise ValueError("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured")

    return (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )

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

def _build_confluence_html(doc: dict) -> str:
    mitre_rows = ""
    tactics = doc.get("mitre_tactics", [])

    if tactics:
        for t in tactics:
            mitre_rows += f"<tr><td>{t}</td><td></td></tr>"
    else:
        mitre_rows = "<tr><td>N/A</td><td>N/A</td></tr>"

    entities_html = ""
    for e in doc.get("kql", {}).get("entity_field_hints", []):
        entities_html += f"<li>{e}</li>"
    if not entities_html:
        entities_html = "<li>N/A</li>"

    tables = ", ".join(doc.get("kql", {}).get("tables_used", [])) or "Not detected"

    return CONFLUENCE_TEMPLATE.format(
        severity=doc.get("severity", "N/A"),
        rule_name=doc.get("rule_display_name", "N/A"),
        mitre_rows=mitre_rows,
        kill_chain_phase="Detection / Command & Control",
        tables=tables,
        query_frequency=doc.get("schedule", {}).get("query_frequency", "N/A"),
        query_period=doc.get("schedule", {}).get("query_period", "N/A"),
        kql=doc.get("kql", {}).get("query", ""),
        entities=entities_html,
    )

# ============================================================
# TOOLS
# ============================================================

_register_tool_def(
    "get_tools",
    "Returns the exact MCP tool list and parameter formats.",
    {}
)

@mcp.tool
def get_tools() -> dict:
    return _ok({"tools": _TOOL_DEFS, "mcp_path": "/mcp"})

_register_tool_def(
    "ping",
    "Connectivity test for the MCP endpoint (does not query Sentinel).",
    {}
)

@mcp.tool
def ping() -> dict:
    return _ok({
        "message": "pong",
        "workspace_configured": bool(WORKSPACE_ID),
        "catalog_loaded": bool(WORKSPACE_TABLE_CATALOG),
        "mcp_path": "/mcp",
    })

_register_tool_def(
    "debug_identity",
    "Shows whether managed identity environment variables are present.",
    {}
)

@mcp.tool
def debug_identity() -> dict:
    return _ok({
        "IDENTITY_ENDPOINT_present": bool(os.environ.get("IDENTITY_ENDPOINT")),
        "IDENTITY_HEADER_present": bool(os.environ.get("IDENTITY_HEADER")),
        "MSI_ENDPOINT_present": bool(os.environ.get("MSI_ENDPOINT")),
        "MSI_SECRET_present": bool(os.environ.get("MSI_SECRET")),
        "MANAGED_IDENTITY_CLIENT_ID_present": bool(os.environ.get("MANAGED_IDENTITY_CLIENT_ID")),
    })

_register_tool_def(
    "get_workspace_table_catalog",
    "Returns the catalog of workspace tables grouped by telemetry type.",
    {}
)

@mcp.tool
def get_workspace_table_catalog() -> dict:
    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded", code="CATALOG_NOT_LOADED")
    return _ok({"catalog": WORKSPACE_TABLE_CATALOG})

_register_tool_def(
    "debug_catalog_loaded",
    "Returns whether the workspace catalog loaded and which keys are present.",
    {}
)

@mcp.tool
def debug_catalog_loaded() -> dict:
    return _ok({
        "loaded": bool(WORKSPACE_TABLE_CATALOG),
        "keys": list(WORKSPACE_TABLE_CATALOG.keys())
    })

_register_tool_def(
    "list_workspace_tables",
    "Returns all unique tables from the workspace table catalog.",
    {}
)

@mcp.tool
def list_workspace_tables() -> dict:
    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded", code="CATALOG_NOT_LOADED")
    return _ok({"tables": _flatten_catalog_tables()})

_register_tool_def(
    "list_tables",
    "Lists tables that ingested data within the given timespan using the Usage table.",
    {"timespan": "ISO8601 duration like P1D, PT6H, PT24H"}
)

@mcp.tool
def list_tables(timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

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
    columns, rows = _la_first_table_rows(payload)

    if not columns:
        return _fail("No tables returned from Log Analytics", code="EMPTY_RESULT", timespan=timespan)

    if "DataType" not in columns:
        return _fail("Unexpected response shape: DataType column not present", code="PARSE_ERROR", timespan=timespan)

    idx = columns.index("DataType")
    return _ok({"tables": [row[idx] for row in rows]}, timespan=timespan)

_register_tool_def(
    "preview_table",
    "Shows a small preview (10 rows) from the specified table.",
    {"table": "Table name string", "timespan": "ISO8601 duration"}
)

@mcp.tool
def preview_table(table: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        table = validate_table_name(table)
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    kql = f"{table} | take 10"
    return la_query(kql, timespan)

_register_tool_def(
    "get_table_schema",
    "Retrieves the schema (columns and types) for the specified table.",
    {"table": "Table name string", "timespan": "ISO8601 duration"}
)

@mcp.tool
def get_table_schema(table: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        table = validate_table_name(table)
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    kql = f"{table} | getschema"
    return la_query(kql, timespan)

_register_tool_def(
    "run_query",
    "Runs a bounded KQL query for the given timespan and returns up to max_rows rows.",
    {"kql": "KQL string", "timespan": "ISO8601 duration", "max_rows": "integer <= 200"}
)

@mcp.tool
def run_query(kql: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    if not kql or not isinstance(kql, str):
        return _fail("kql is required", code="VALIDATION_ERROR")

    try:
        kql_safety_check(kql)
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid query input", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_RUN_QUERY:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_RUN_QUERY}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h"
        )

    bounded_kql = ensure_take_limit(kql, clamp_rows(max_rows))
    return la_query(bounded_kql, timespan)

_register_tool_def(
    "list_analytics_rules",
    "Lists Microsoft Sentinel analytics rules in the configured workspace.",
    {"top": "optional int; max rules to return (default 50, hard cap 200)"}
)

@mcp.tool
def list_analytics_rules(top: int = 50) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail(
            "SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
            code="CONFIG_ERROR"
        )

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

_register_tool_def(
    "analyze_use_case",
    "Fetch Sentinel analytic rule by rule_id or rule_name and extract documentation-ready key points.",
    {
        "rule_id": "optional: analytic rule ARM resource name/guid",
        "rule_name": "optional: displayName match (case-insensitive exact match preferred)"
    }
)

@mcp.tool
def analyze_use_case(
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail(
            "SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
            code="CONFIG_ERROR"
        )

    rid = (rule_id or "").strip()
    rname = (rule_name or "").strip()

    if not rid and not rname:
        return _fail("Provide rule_id or rule_name", code="VALIDATION_ERROR")

    if not rid and rname:
        rid = _find_rule_id_by_name(rname) or ""
        if not rid:
            return _fail("Rule not found by name", code="NOT_FOUND", detail="Try list_analytics_rules")

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

_register_tool_def(
    "generate_confluence_use_case",
    "Generate a Confluence-ready documentation page for a Sentinel analytic rule.",
    {
        "rule_id": "optional: analytic rule ARM resource name/guid",
        "rule_name": "optional: displayName match (case-insensitive exact match preferred)"
    }
)

@mcp.tool
def generate_confluence_use_case(
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail(
            "SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
            code="CONFIG_ERROR"
        )

    rid = (rule_id or "").strip()
    rname = (rule_name or "").strip()

    if not rid and not rname:
        return _fail("Provide rule_id or rule_name", code="VALIDATION_ERROR")

    if not rid and rname:
        rid = _find_rule_id_by_name(rname) or ""
        if not rid:
            return _fail("Rule not found by name", code="NOT_FOUND")

    res = _fetch_rule_by_id(rid)
    if not res.get("ok"):
        return res

    rule = res["data"] or {}
    props = rule.get("properties") or {}
    kql = props.get("query") or ""

    doc = {
        "rule_display_name": props.get("displayName"),
        "severity": props.get("severity"),
        "mitre_tactics": props.get("tactics") or [],
        "mitre_techniques": props.get("techniques") or [],
        "schedule": {
            "query_frequency": props.get("queryFrequency"),
            "query_period": props.get("queryPeriod"),
        },
        "kql": {
            "query": kql,
            "tables_used": _extract_tables_from_kql(kql),
            "entity_field_hints": _detect_entity_hints(kql),
        },
    }

    html = _build_confluence_html(doc)

    return _ok({
        "rule_name": props.get("displayName"),
        "confluence_html": html
    })

_register_tool_def(
    "analyze_entity",
    "SOC-style entity investigation across common Sentinel tables. Supports ip, user, host, domain, hash.",
    {
        "value": "Entity string (IP, UPN, hostname, domain, hash, etc.)",
        "timespan": "ISO8601 duration (PT6H, P1D, P7D)",
        "max_rows": "integer <= 200"
    }
)

@mcp.tool
def analyze_entity(value: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    if not value:
        return _fail("value is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h"
        )

    entity_type = detect_entity_type(value)
    safe_value = escape_kql_string(value)
    max_rows = clamp_rows(max_rows)

    preferred_domains = _catalog_domains_for_entity(entity_type)
    preferred_tables = set(_catalog_tables_for_domains(preferred_domains))

    table_map = {
        "ip": [
            ("SigninLogs", f'IPAddress == "{safe_value}"'),
            ("SecurityAlert", f'CompromisedEntity contains "{safe_value}" or tostring(Entities) contains "{safe_value}"'),
            ("AzureActivity", f'CallerIpAddress == "{safe_value}"'),
            ("DeviceNetworkEvents", f'RemoteIP == "{safe_value}" or LocalIP == "{safe_value}"'),
        ],
        "user": [
            ("SigninLogs", f'UserPrincipalName =~ "{safe_value}"'),
            ("SecurityEvent", f'Account =~ "{safe_value}"'),
            ("AuditLogs", f'tostring(InitiatedBy.user.userPrincipalName) =~ "{safe_value}"'),
            ("DeviceLogonEvents", f'AccountName =~ "{safe_value}" or InitiatingProcessAccountUpn =~ "{safe_value}"'),
        ],
        "domain": [
            ("DeviceNetworkEvents", f'RemoteUrl contains "{safe_value}"'),
            ("UrlClickEvents", f'Url contains "{safe_value}"'),
            ("EmailUrlInfo", f'Url contains "{safe_value}"'),
        ],
        "sha256": [
            ("DeviceFileEvents", f'SHA256 == "{safe_value}"'),
        ],
        "sha1": [
            ("DeviceFileEvents", f'SHA1 == "{safe_value}"'),
        ],
        "md5": [
            ("DeviceFileEvents", f'MD5 == "{safe_value}"'),
        ],
        "host": [
            ("DeviceInfo", f'DeviceName =~ "{safe_value}"'),
            ("DeviceEvents", f'DeviceName =~ "{safe_value}"'),
            ("DeviceProcessEvents", f'DeviceName =~ "{safe_value}"'),
            ("SecurityAlert", f'CompromisedEntity contains "{safe_value}" or tostring(Entities) contains "{safe_value}"'),
        ],
    }

    queries = table_map.get(entity_type, [])[:6]

    findings = []
    total_events = 0
    risk_score = 0
    tables_checked = []

    for table, where_clause in queries:
        if preferred_tables and table not in preferred_tables:
            continue

        tables_checked.append(table)

        summary_kql = f"""
{table}
| where {where_clause}
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
""".strip()

        res = la_query(summary_kql, timespan)
        if not res.get("ok"):
            continue

        rows = _la_first_table_dicts(res["data"])
        if not rows:
            continue

        row = rows[0]
        count = int(row.get("Count") or 0)
        first_seen = row.get("FirstSeen")
        last_seen = row.get("LastSeen")

        if count == 0:
            continue

        total_events += count

        if count > 100:
            risk_score += 2
        elif count > 20:
            risk_score += 1

        if table in ["SecurityEvent", "AuditLogs", "SecurityAlert"]:
            risk_score += 1

        findings.append({
            "table": table,
            "count": count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    cmdb_context = None
    if entity_type in {"ip", "host", "domain"}:
        cmdb_res = _query_cmdb_entity(value, timespan)
        if cmdb_res.get("ok"):
            cmdb_context = cmdb_res["data"]

    if risk_score >= 4:
        risk_level = "High"
    elif risk_score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return _ok({
        "entity": value,
        "entity_type": entity_type,
        "timespan": timespan,
        "telemetry_domains_checked": preferred_domains,
        "tables_checked": tables_checked,
        "tables_hit": len(findings),
        "total_events": total_events,
        "risk_level": risk_level,
        "cmdb_context": cmdb_context,
        "results": findings,
    })

_register_tool_def(
    "get_incident_report",
    "List Sentinel incidents or generate a SOC incident report. If incident_id is omitted, returns recent incidents.",
    {
        "incident_id": "optional: Sentinel incident number or name",
        "timespan": "ISO8601 duration like P1D, P7D",
        "top": "optional number of incidents to list (default 10)"
    }
)

@mcp.tool
def get_incident_report(
    incident_id: Optional[str] = None,
    timespan: str = "P7D",
    top: int = 50
) -> dict:
    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    top = clamp_rows(top)

    if not incident_id:
        kql = f"""
SecurityIncident
| where Severity !~ "Informational"
| sort by CreatedTime desc
| project IncidentNumber, Title, Severity, Status, Owner, CreatedTime, LastModifiedTime
| take {top}
""".strip()

        res = la_query(kql, timespan)
        if not res.get("ok"):
            return res

        incidents = _la_first_table_dicts(res["data"])
        if not incidents:
            return _fail("No incidents found", code="EMPTY_RESULT")

        return _ok({
            "mode": "list",
            "count": len(incidents),
            "incidents": incidents
        })

    safe_id = escape_kql_string(str(incident_id))

    kql = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| project IncidentNumber, Title, Severity, Status, Owner, CreatedTime, LastModifiedTime, AlertIds
| mv-expand AlertIds
| extend AlertIdStr = tostring(AlertIds)
| join kind=leftouter (
    SecurityAlert
    | project
        SystemAlertId,
        AlertName = ProductName,
        AlertComponent = ProductComponentName,
        AlertStatus = Status,
        AlertTime = StartTime,
        CompromisedEntity,
        Tactics,
        Techniques,
        Entities
    | extend AlertIdStr = tostring(SystemAlertId)
) on AlertIdStr
| summarize
    Alerts = countif(isnotempty(AlertIdStr)),
    AlertNames = make_set(AlertName, 10),
    AlertComponents = make_set(AlertComponent, 10),
    AlertStatuses = make_set(AlertStatus, 10),
    CompromisedEntities = make_set(CompromisedEntity, 10),
    TacticsSet = make_set(Tactics, 10),
    TechniquesSet = make_set(Techniques, 10),
    FirstAlert = min(AlertTime),
    LastAlert = max(AlertTime)
    by IncidentNumber, Title, Severity, Status, Owner, CreatedTime, LastModifiedTime
""".strip()

    res = la_query(kql, timespan)
    if not res.get("ok"):
        return res

    incidents = _la_first_table_dicts(res["data"])
    if not incidents:
        return _fail("Incident not found", code="NOT_FOUND")

    incident = incidents[0]
    severity = (incident.get("Severity") or "").lower()

    if severity == "high":
        risk = "High"
    elif severity == "medium":
        risk = "Medium"
    else:
        risk = "Low"

    return _ok({
        "mode": "report",
        "incident_number": incident.get("IncidentNumber"),
        "title": incident.get("Title"),
        "severity": incident.get("Severity"),
        "status": incident.get("Status"),
        "owner": incident.get("Owner"),
        "created_time": incident.get("CreatedTime"),
        "last_modified": incident.get("LastModifiedTime"),
        "alerts_count": incident.get("Alerts"),
        "alert_names": incident.get("AlertNames"),
        "alert_components": incident.get("AlertComponents"),
        "alert_statuses": incident.get("AlertStatuses"),
        "compromised_entities": incident.get("CompromisedEntities"),
        "tactics": incident.get("TacticsSet"),
        "techniques": incident.get("TechniquesSet"),
        "first_alert": incident.get("FirstAlert"),
        "last_alert": incident.get("LastAlert"),
        "risk_level": risk
    })

_register_tool_def(
    "investigate_incident",
    "SOC investigation of a Microsoft Sentinel incident. Extracts alerts, entities, MITRE techniques, and timeline indicators.",
    {
        "incident_id": "Sentinel incident number",
        "timespan": "ISO8601 duration (P1D, P7D)"
    }
)

@mcp.tool
def investigate_incident(incident_id: str, timespan: str = "P7D") -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_INCIDENT:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_INCIDENT}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h"
        )

    safe_id = escape_kql_string(str(incident_id))

    incident_kql = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| where Severity !~ "Informational"
| project IncidentNumber, Title, Severity, Status, Owner, CreatedTime, LastModifiedTime, AlertIds
""".strip()

    inc_res = la_query(incident_kql, timespan)
    if not inc_res.get("ok"):
        return inc_res

    incident_rows = _la_first_table_dicts(inc_res["data"])
    if not incident_rows:
        return _fail("Incident not found", code="NOT_FOUND")

    incident = incident_rows[0]
    alert_ids = incident.get("AlertIds") or []

    if isinstance(alert_ids, str):
        try:
            alert_ids = json.loads(alert_ids)
        except Exception:
            alert_ids = []

    if not alert_ids:
        return _ok({
            "incident": incident,
            "alerts": [],
            "entities": {},
            "timeline": {},
            "mitre": {},
            "risk_level": "Low",
            "assessment": "Incident has no linked alerts"
        })

    safe_alerts = [escape_kql_string(str(a)) for a in alert_ids if a]
    alert_list = ",".join([f'"{a}"' for a in safe_alerts])

    alerts_kql = f"""
SecurityAlert
| where SystemAlertId in ({alert_list})
| project
    AlertName = ProductName,
    Component = ProductComponentName,
    AlertTime = StartTime,
    Status,
    CompromisedEntity,
    Tactics,
    Techniques,
    Entities
""".strip()

    alert_res = la_query(alerts_kql, timespan)
    if not alert_res.get("ok"):
        return alert_res

    alerts = _la_first_table_dicts(alert_res["data"])

    users = set()
    ips = set()
    hosts = set()
    domains = set()

    for alert in alerts:
        entities = alert.get("Entities")
        if not entities:
            continue

        try:
            ent_list = json.loads(entities) if isinstance(entities, str) else entities
        except Exception:
            continue

        if not isinstance(ent_list, list):
            continue

        for e in ent_list:
            if not isinstance(e, dict):
                continue

            etype = (e.get("Type") or "").lower()

            if etype == "account":
                if e.get("Name"):
                    users.add(e.get("Name"))

            elif etype == "ip":
                if e.get("Address"):
                    ips.add(e.get("Address"))

            elif etype in ["host", "machine"]:
                if e.get("HostName"):
                    hosts.add(e.get("HostName"))

            elif etype == "dns":
                if e.get("DomainName"):
                    domains.add(e.get("DomainName"))

    alert_times = [a.get("AlertTime") for a in alerts if a.get("AlertTime")]
    first_alert = min(alert_times) if alert_times else None
    last_alert = max(alert_times) if alert_times else None

    tactics = sorted({a.get("Tactics") for a in alerts if a.get("Tactics")})
    techniques = sorted({a.get("Techniques") for a in alerts if a.get("Techniques")})

    cmdb_context = []

    for pivot in list(ips)[:3] + list(hosts)[:3] + list(domains)[:3]:
        cmdb_res = _query_cmdb_entity(str(pivot), timespan)
        if cmdb_res.get("ok"):
            cmdb_context.append({
                "entity": pivot,
                "result": cmdb_res["data"]
            })

    risk_score = 0
    sev = (incident.get("Severity") or "").lower()

    if sev == "high":
        risk_score += 4
    elif sev == "medium":
        risk_score += 2
    else:
        risk_score += 1

    if len(alerts) > 5:
        risk_score += 2
    if ips:
        risk_score += 1
    if users:
        risk_score += 1
    if hosts:
        risk_score += 1

    if risk_score >= 6:
        risk_level = "High"
    elif risk_score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return _ok({
        "incident": {
            "id": incident.get("IncidentNumber"),
            "title": incident.get("Title"),
            "severity": incident.get("Severity"),
            "status": incident.get("Status"),
            "owner": incident.get("Owner"),
            "created_time": incident.get("CreatedTime"),
            "last_modified_time": incident.get("LastModifiedTime"),
        },
        "alerts": {
            "count": len(alerts),
            "names": sorted({a.get("AlertName") for a in alerts if a.get("AlertName")}),
            "components": sorted({a.get("Component") for a in alerts if a.get("Component")}),
        },
        "entities": {
            "users": sorted(users),
            "ips": sorted(ips),
            "hosts": sorted(hosts),
            "domains": sorted(domains),
        },
        "timeline": {
            "first_alert": first_alert,
            "last_alert": last_alert,
        },
        "mitre": {
            "tactics": tactics,
            "techniques": techniques,
        },
        "asset_context": cmdb_context,
        "risk_level": risk_level
    })

# ============================================================
# EXPORT ASGI APP
# ============================================================

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
