from fastmcp import FastMCP
import requests
import os
import re
import json
import urllib.request

# ============================
# MCP Setup
# ============================

mcp = FastMCP("SentinelMCP")

# ============================
# Configuration
# ============================

LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"

WORKSPACE_ID = os.environ.get("WORKSPACE_ID")

MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50
MAX_HOURS = 24
DEFAULT_TIMESPAN = "PT1H"

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
# Guardrails
# ============================

def parse_timespan_to_hours(timespan: str) -> float:
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan)
    if m:
        return int(m.group(1) or 0) + int(m.group(2) or 0) / 60.0
    d = re.fullmatch(r"P(\d+)D", timespan)
    if d:
        return int(d.group(1)) * 24.0
    raise ValueError("Invalid timespan format. Use PT1H, PT6H, PT24H.")

def clamp_rows(n):
    try:
        v = int(n)
    except:
        v = DEFAULT_ROWS
    return max(1, min(v, MAX_ROWS_HARD))

def kql_safety_check(kql: str):
    lowered = kql.lower()

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' not allowed")

    for blocked in ["externaldata", "evaluate", "make-series", "mv-expand"]:
        if blocked in lowered:
            raise ValueError(f"KQL contains blocked operator: {blocked}")

def ensure_take_limit(kql: str, limit: int):
    lowered = kql.lower()
    if "| take" in lowered or "| limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

# ============================
# Log Analytics Query
# ============================

def la_query(kql: str, timespan: str):
    if not WORKSPACE_ID:
        return {"error": "WORKSPACE_ID not configured"}

    token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "query": kql,
            "timespan": timespan
        },
        timeout=60
    )

    if not response.ok:
        return {
            "error": True,
            "status_code": response.status_code,
            "detail": response.text
        }

    return response.json()

# ============================
# Tools
# ============================

@mcp.tool
def list_tables(timespan: str = DEFAULT_TIMESPAN) -> dict:
    """
    List tables that ingested data within the given timespan.
    Uses the Usage table (most reliable method).
    """

    kql = """
    Usage
    | where Quantity > 0
    | summarize Count=sum(Quantity) by DataType
    | order by Count desc
    | take 50
    """

    result = la_query(kql, timespan)

    # If query failed, return raw result
    if "tables" not in result or not result["tables"]:
        return result

    table = result["tables"][0]
    columns = [c["name"] for c in table["columns"]]
    rows = table["rows"]

    try:
        idx = columns.index("DataType")
    except ValueError:
        return result

    return {
        "tables": [row[idx] for row in rows]
    }


@mcp.tool
def preview_table(table: str) -> dict:
    """
    Preview 10 rows from a table.
    """
    kql = f"{table} | take 10"
    return la_query(kql, DEFAULT_TIMESPAN)


@mcp.tool
def get_table_schema(table: str) -> dict:
    """
    Get schema of a table.
    """
    kql = f"{table} | getschema"
    return la_query(kql, DEFAULT_TIMESPAN)


@mcp.tool
def run_query(kql: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    """
    Run a bounded KQL query (max 24h timespan).
    """
    kql_safety_check(kql)

    hours = parse_timespan_to_hours(timespan)
    if hours <= 0 or hours > MAX_HOURS:
        return {"error": f"Timespan exceeds allowed window ({MAX_HOURS}h max)"}

    kql = ensure_take_limit(kql, clamp_rows(max_rows))

    return la_query(kql, timespan)

# ============================
# Export ASGI App (IMPORTANT)
# ============================

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
