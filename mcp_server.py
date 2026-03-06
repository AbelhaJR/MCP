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

# ============================
# Workspace Table Catalog
# ============================

TABLE_CATALOG_PATH = os.environ.get("TABLE_CATALOG_PATH", "workspace_tables.json")

WORKSPACE_TABLE_CATALOG = {}

try:
    with open(TABLE_CATALOG_PATH, "r") as f:
        WORKSPACE_TABLE_CATALOG = json.load(f)
except Exception:
    WORKSPACE_TABLE_CATALOG = {}



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
MAX_HOURS_RUN_QUERY = 72

# For listing tables, P1D is the most intuitive default
DEFAULT_TIMESPAN = os.environ.get("DEFAULT_TIMESPAN", "P3D")

# Lower timeout to avoid Teams/M365 action timeouts masking the real error
HTTP_TIMEOUT_SECONDS = int(os.environ.get("LA_HTTP_TIMEOUT", "15"))

# ============================
# Managed Identity
# ============================

# Cache token briefly to avoid repeated MSI calls in short bursts
_TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}

def get_managed_identity_token(resource: str) -> str:
    now = int(time.time())

    # Per-resource cache
    cached = _TOKEN_CACHE.get(resource)
    if cached:
        if cached["exp"] - now > 60:
            return cached["token"]

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

            _TOKEN_CACHE[resource] = {
                "token": token,
                "exp": now + expires_in,
            }

            return token

    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")

    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
        token = payload["access_token"]
        expires_in = int(payload.get("expires_in") or 300)

        _TOKEN_CACHE[resource] = {
            "token": token,
            "exp": now + expires_in,
        }

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
# Advanced SOC Entity Analysis Tool
# ============================

MAX_HOURS_ANALYZE_ENTITY = 168  # 7 days max window


def escape_kql_string(s: str) -> str:
    """Escape quotes for safe KQL usage."""
    return (s or "").replace('"', '""')


def detect_entity_type(value: str) -> str:
    """Basic entity classification."""
    v = (value or "").strip()

    # IPv4
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        try:
            parts = [int(x) for x in v.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return "ip"
        except Exception:
            pass

    # User (UPN / email)
    if "@" in v:
        return "user"

    # Hashes
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"

    # Domain
    if "." in v:
        return "domain"

    return "generic"


# Add tool to inventory
_TOOL_DEFS.append(
    {
        "name": "analyze_entity",
        "description": "SOC-style entity investigation across common Sentinel tables. Supports ip, user, host, domain, hash.",
        "params": {
            "value": "Entity string (IP, UPN, hostname, domain, hash, etc.)",
            "timespan": "ISO8601 duration (PT6H, P1D, P7D)",
            "max_rows": "integer <= 200"
        },
    }
)


@mcp.tool
def analyze_entity(value: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    """
    SOC-style entity investigation.
    Copilot-safe version (no raw rows returned).
    """

    if not value:
        return _fail("value is required")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)",
            detail=f"got {hours}h"
        )

    entity_type = detect_entity_type(value)
    safe_value = escape_kql_string(value)

    table_map = {
        "ip": [
            ("SigninLogs", f'IPAddress == "{safe_value}"'),
            ("SecurityEvent", f'IpAddress == "{safe_value}"'),
            ("AzureActivity", f'CallerIpAddress == "{safe_value}"'),
            ("DeviceNetworkEvents", f'RemoteIP == "{safe_value}"'),
        ],
        "user": [
            ("SigninLogs", f'UserPrincipalName =~ "{safe_value}"'),
            ("SecurityEvent", f'Account =~ "{safe_value}"'),
            ("AuditLogs", f'tostring(InitiatedBy.user.userPrincipalName) =~ "{safe_value}"'),
            ("DeviceLogonEvents", f'AccountName =~ "{safe_value}"'),
        ],
        "domain": [
            ("DeviceNetworkEvents", f'RemoteUrl contains "{safe_value}"'),
        ],
        "sha256": [
            ("DeviceFileEvents", f'SHA256 == "{safe_value}"'),
        ],
        "generic": [
            ("SigninLogs", f'tostring(*) contains "{safe_value}"'),
        ],
    }

    queries = table_map.get(entity_type, table_map["generic"])[:5]

    findings = []
    total_events = 0
    risk_score = 0

    for table, where_clause in queries:

        summary_kql = f"""
        {table}
        | where {where_clause}
        | summarize Count=count(),
                    FirstSeen=min(TimeGenerated),
                    LastSeen=max(TimeGenerated)
        """

        res = la_query(summary_kql, timespan)
        if not res.get("ok"):
            continue

        tables = res["data"].get("tables") or []
        if not tables or not tables[0].get("rows"):
            continue

        row = tables[0]["rows"][0]
        count, first_seen, last_seen = row

        if count == 0:
            continue

        total_events += count

        # Simple SOC risk heuristics
        if count > 100:
            risk_score += 2
        if table in ["SecurityEvent", "AuditLogs"]:
            risk_score += 1

        findings.append({
            "table": table,
            "count": count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    # Risk classification
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
        "tables_hit": len(findings),
        "total_events": total_events,
        "risk_level": risk_level,
        "results": findings,
    })


_TOOL_DEFS.append(
    {
        "name": "generate_confluence_use_case",
        "description": "Generate a Confluence-ready documentation page for a Sentinel analytic rule.",
        "params": {
            "rule_id": "optional: analytic rule ARM resource name/guid",
            "rule_name": "optional: displayName match (case-insensitive exact match preferred)"
        },
    }
)
def _build_confluence_html(doc: dict) -> str:
    mitre_rows = ""
    tactics = doc.get("mitre_tactics", [])
    techniques = doc.get("mitre_techniques", [])

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
@mcp.tool
def generate_confluence_use_case(
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
            return _fail("Rule not found by name")

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

_TOOL_DEFS.append(
    {
        "name": "get_incident_report",
        "description": "List Sentinel incidents or generate a SOC incident report. If incident_id is omitted, returns recent incidents.",
        "params": {
            "incident_id": "optional: Sentinel incident number or name",
            "timespan": "ISO8601 duration like P1D, P7D",
            "top": "optional number of incidents to list (default 10)"
        },
    }
)
@mcp.tool
def get_incident_report(
    incident_id: Optional[str] = None,
    timespan: str = "P7D",
    top: int = 10
) -> dict:
    """
    If incident_id is not provided → list recent incidents.
    If incident_id is provided → return detailed incident report.
    """

    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", detail=str(e))

    top = clamp_rows(top)

    # --------------------------------
    # MODE 1 — LIST INCIDENTS
    # --------------------------------
    if not incident_id:

        kql = f"""
SecurityIncident
| where Severity !~ "Informational"
| sort by CreatedTime desc
| project
    IncidentNumber,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime
| take {top}
"""

        res = la_query(kql, timespan)

        if not res.get("ok"):
            return res

        tables = res["data"].get("tables") or []
        if not tables:
            return _fail("No incidents found")

        cols = [c["name"] for c in tables[0]["columns"]]

        incidents = [
            dict(zip(cols, r))
            for r in tables[0]["rows"]
        ]

        return _ok({
            "mode": "list",
            "count": len(incidents),
            "incidents": incidents
        })

    # --------------------------------
    # MODE 2 — INCIDENT REPORT
    # --------------------------------

    safe_id = escape_kql_string(str(incident_id))

    kql = f"""
SecurityIncident
| where IncidentNumber == {safe_id} or IncidentName =~ "{safe_id}"
| project
    IncidentNumber,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime,
    AlertIds
| mv-expand AlertIds
| join kind=leftouter (
    SecurityAlert
    | project
        AlertId,
        AlertName=DisplayName,
        AlertSeverity=Severity,
        AlertTime=TimeGenerated,
        ProviderName,
        Entities
) on $left.AlertIds == $right.AlertId
| summarize
    Alerts=count(),
    AlertNames=make_set(AlertName,10),
    Providers=make_set(ProviderName,10),
    FirstAlert=min(AlertTime),
    LastAlert=max(AlertTime)
    by
    IncidentNumber,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime
"""

    res = la_query(kql, timespan)

    if not res.get("ok"):
        return res

    tables = res["data"].get("tables") or []
    if not tables or not tables[0].get("rows"):
        return _fail("Incident not found")

    cols = [c["name"] for c in tables[0]["columns"]]
    row = tables[0]["rows"][0]

    incident = dict(zip(cols, row))

    # Risk heuristic
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
        "providers": incident.get("Providers"),
        "first_alert": incident.get("FirstAlert"),
        "last_alert": incident.get("LastAlert"),
        "risk_level": risk
    })


_TOOL_DEFS.append(
    {
        "name": "investigate_incident",
        "description": "SOC investigation of a Microsoft Sentinel incident. Extracts alerts, entities, MITRE techniques, and timeline indicators.",
        "params": {
            "incident_id": "Sentinel incident number",
            "timespan": "ISO8601 duration (P1D, P7D)"
        },
    }
)


@mcp.tool
def investigate_incident(incident_id: str, timespan: str = "P7D") -> dict:
    """
    SOC-style Sentinel incident investigation.
    Extracts alerts, entities, timeline, and MITRE indicators.
    """

    if not incident_id:
        return _fail("incident_id is required")

    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", detail=str(e))

    safe_id = escape_kql_string(str(incident_id))

    # -----------------------------------
    # STEP 1 — INCIDENT METADATA
    # -----------------------------------

    incident_kql = f"""
SecurityIncident
| where IncidentNumber == {safe_id}
| project
    IncidentNumber,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime,
    AlertIds
"""

    inc_res = la_query(incident_kql, timespan)

    if not inc_res.get("ok"):
        return inc_res

    tables = inc_res["data"].get("tables") or []
    if not tables or not tables[0]["rows"]:
        return _fail("Incident not found")

    cols = [c["name"] for c in tables[0]["columns"]]
    row = tables[0]["rows"][0]

    incident = dict(zip(cols, row))

    alert_ids = incident.get("AlertIds") or []

    # Handle dynamic/string AlertIds
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

    alert_list = ",".join([f'"{escape_kql_string(a)}"' for a in alert_ids])

    # -----------------------------------
    # STEP 2 — ALERT INVESTIGATION
    # -----------------------------------

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
"""

    alert_res = la_query(alerts_kql, timespan)

    if not alert_res.get("ok"):
        return alert_res

    tables = alert_res["data"].get("tables") or []

    if not tables:
        alerts = []
    else:
        cols = [c["name"] for c in tables[0]["columns"]]
        alerts = [dict(zip(cols, r)) for r in tables[0]["rows"]]

    # -----------------------------------
    # STEP 3 — ENTITY EXTRACTION
    # -----------------------------------

    users = set()
    ips = set()
    hosts = set()

    for alert in alerts:

        entities = alert.get("Entities")

        if not entities:
            continue

        try:
            ent_list = json.loads(entities)
        except Exception:
            continue

        for e in ent_list:

            etype = (e.get("Type") or "").lower()

            if etype == "account":
                users.add(e.get("Name"))

            elif etype == "ip":
                ips.add(e.get("Address"))

            elif etype in ["host", "machine"]:
                hosts.add(e.get("HostName"))

    # -----------------------------------
    # STEP 4 — TIMELINE
    # -----------------------------------

    alert_times = [a.get("AlertTime") for a in alerts if a.get("AlertTime")]

    first_alert = min(alert_times) if alert_times else None
    last_alert = max(alert_times) if alert_times else None

    # -----------------------------------
    # STEP 5 — MITRE EXTRACTION
    # -----------------------------------

    tactics = set()
    techniques = set()

    for alert in alerts:

        if alert.get("Tactics"):
            tactics.add(alert.get("Tactics"))

        if alert.get("Techniques"):
            techniques.add(alert.get("Techniques"))

    # -----------------------------------
    # STEP 6 — RISK SCORING
    # -----------------------------------

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

    # -----------------------------------
    # STEP 7 — FINAL REPORT
    # -----------------------------------

    return _ok({

        "incident": {
            "id": incident.get("IncidentNumber"),
            "title": incident.get("Title"),
            "severity": incident.get("Severity"),
            "status": incident.get("Status"),
            "owner": incident.get("Owner"),
            "created_time": incident.get("CreatedTime"),
        },

        "alerts": {
            "count": len(alerts),
            "names": list({a.get("AlertName") for a in alerts if a.get("AlertName")}),
            "components": list({a.get("Component") for a in alerts if a.get("Component")}),
        },

        "entities": {
            "users": list(users),
            "ips": list(ips),
            "hosts": list(hosts),
        },

        "timeline": {
            "first_alert": first_alert,
            "last_alert": last_alert,
        },

        "mitre": {
            "tactics": list(tactics),
            "techniques": list(techniques),
        },

        "risk_level": risk_level
    })

_TOOL_DEFS.append(
{
    "name": "list_workspace_tables",
    "description": "List all tables available in the Log Analytics workspace.",
    "params": {}
}
)

@mcp.tool
def list_workspace_tables() -> dict:

    kql = """
    .show tables
    | project TableName
    """

    res = la_query(kql, "P1D")

    if not res.get("ok"):
        return res

    tables = res["data"]["tables"][0]["rows"]

    return _ok({
        "tables": [t[0] for t in tables]
    })

_TOOL_DEFS.append(
{
    "name": "get_workspace_table_catalog",
    "description": "Returns the catalog of workspace tables grouped by telemetry type.",
    "params": {}
}
@mcp.tool
def get_workspace_table_catalog() -> dict:
    """
    Return workspace table catalog used for investigations.
    """

    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded")

    return _ok({
        "catalog": WORKSPACE_TABLE_CATALOG
    })
    
)
# ============================
# Export ASGI App (IMPORTANT)
# ============================

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
