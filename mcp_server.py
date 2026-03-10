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
DEFAULT_SIMILAR_DAYS = 30

CMDB_TABLE = "COVERAGE_CMDB"

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
_HASH_64_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_HASH_40_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_HASH_32_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

def parse_timespan_to_hours(timespan: str) -> float:
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

    if _HASH_64_RE.fullmatch(v):
        return "sha256"

    if _HASH_40_RE.fullmatch(v):
        return "sha1"

    if _HASH_32_RE.fullmatch(v):
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

def _normalize_title_for_family(title: str) -> str:
    s = (title or "").strip().lower()
    s = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", s)
    s = re.sub(r"\b[a-f0-9]{32,64}\b", "<hash>", s)
    s = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,36}\b", "<guid>", s)
    s = re.sub(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", "<user>", s)
    s = re.sub(r"\b[a-z0-9][a-z0-9._-]{2,}\b", lambda m: m.group(0), s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _entity_priority_score(entity_type: str, value: str) -> int:
    base = {
        "host": 5,
        "ip": 5,
        "user": 4,
        "domain": 4,
        "sha256": 4,
        "sha1": 4,
        "md5": 4,
        "url": 3,
    }.get(entity_type, 1)

    if value and value != "<unknown>":
        base += 1
    return base

def _dedupe_preserve_order(items: List[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out

def _query_cmdb_entity(value: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    safe_value = escape_kql_string(value)

    structured_kql = f"""
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
    or tostring(logsource) contains "{safe_value}"
| project
    Key,
    Management_IP,
    ApplicationAndComponentInstance,
    Network_Interfaces,
    Updated,
    Scanning_Information,
    BusinessEntity,
    FQDN,
    PSNC,
    logsource
| take 20
""".strip()

    res = la_query(structured_kql, timespan)
    if not res.get("ok"):
        return res

    rows = _la_first_table_dicts(res["data"])
    if rows:
        return res

    fallback_kql = f"""
{CMDB_TABLE}
| where tostring(*) contains "{safe_value}"
| project
    Key,
    Management_IP,
    ApplicationAndComponentInstance,
    Network_Interfaces,
    Updated,
    Scanning_Information,
    BusinessEntity,
    FQDN,
    PSNC,
    logsource
| take 20
""".strip()

    return la_query(fallback_kql, timespan)

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
        "mv-expand", "union", "lookup", "distinct"
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
# INCIDENT / ENTITY HELPERS
# ============================================================

def _sentinel_incident_latest_kql(safe_id: str) -> str:
    return f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| where Severity !~ "Informational"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project
    IncidentNumber,
    IncidentName,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime,
    Classification,
    ClassificationReason,
    ClassificationComment,
    AlertIds,
    Labels,
    AdditionalData
""".strip()

def _parse_alert_ids(raw_alert_ids: Any) -> List[str]:
    if raw_alert_ids is None:
        return []
    if isinstance(raw_alert_ids, list):
        return [str(x) for x in raw_alert_ids if x]
    if isinstance(raw_alert_ids, str):
        try:
            parsed = json.loads(raw_alert_ids)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x]
        except Exception:
            return []
    return []

def _extract_alert_entities(alerts: List[dict]) -> dict:
    entity_map = {
        "users": [],
        "ips": [],
        "hosts": [],
        "domains": [],
        "hashes": [],
        "urls": [],
        "raw": [],
    }

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

            entity_map["raw"].append(e)
            etype = str(e.get("Type") or "").lower()

            if etype == "account":
                value = e.get("UPNSuffix")
                name = e.get("Name")
                if name and value:
                    entity_map["users"].append({
                        "type": "user",
                        "value": f"{name}@{value}",
                        "source": "alert_entities",
                    })
                elif name:
                    entity_map["users"].append({
                        "type": "user",
                        "value": str(name),
                        "source": "alert_entities",
                    })

            elif etype == "ip":
                if e.get("Address"):
                    entity_map["ips"].append({
                        "type": "ip",
                        "value": str(e.get("Address")),
                        "source": "alert_entities",
                    })

            elif etype in ["host", "machine"]:
                host = e.get("HostName") or e.get("DnsDomain")
                if e.get("HostName"):
                    entity_map["hosts"].append({
                        "type": "host",
                        "value": str(e.get("HostName")),
                        "source": "alert_entities",
                    })
                if e.get("DnsDomain"):
                    entity_map["domains"].append({
                        "type": "domain",
                        "value": str(e.get("DnsDomain")),
                        "source": "alert_entities",
                    })

            elif etype == "dns":
                if e.get("DomainName"):
                    entity_map["domains"].append({
                        "type": "domain",
                        "value": str(e.get("DomainName")),
                        "source": "alert_entities",
                    })

            elif etype == "file":
                for algo in ["SHA256", "SHA1", "MD5"]:
                    if e.get(algo):
                        entity_map["hashes"].append({
                            "type": algo.lower(),
                            "value": str(e.get(algo)),
                            "source": "alert_entities",
                        })

            elif etype == "url":
                if e.get("Url"):
                    entity_map["urls"].append({
                        "type": "url",
                        "value": str(e.get("Url")),
                        "source": "alert_entities",
                    })

    for key in entity_map:
        entity_map[key] = _dedupe_preserve_order(entity_map[key])

    return entity_map

def _select_top_entities(entity_map: dict, max_entities: int = 3) -> List[dict]:
    candidates = []
    for bucket in ["hosts", "ips", "users", "domains", "hashes", "urls"]:
        for item in entity_map.get(bucket, []):
            etype = item.get("type") or detect_entity_type(item.get("value", ""))
            candidates.append({
                "type": etype,
                "value": item.get("value"),
                "source": item.get("source", "unknown"),
                "priority": _entity_priority_score(etype, item.get("value", "")),
            })

    candidates.sort(key=lambda x: (-x["priority"], x["type"], x["value"]))
    return candidates[:max(1, min(max_entities, 10))]

def _similar_incident_lookup(title: str, days_i: int = DEFAULT_SIMILAR_DAYS) -> dict:
    normalized_title = _normalize_title_for_family(title)
    safe_title = escape_kql_string(normalized_title)

    exact_kql = f"""
SecurityIncident
| where CreatedTime >= ago({days_i}d)
| where Severity !~ "Informational"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| extend NormalizedFamilyTitle = tolower(trim(@" ", tostring(Title)))
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}\\b", "<ip>")
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b[a-f0-9]{{32,64}}\\b", "<hash>")
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b[0-9a-f]{{8}}-[0-9a-f-]{{27,36}}\\b", "<guid>")
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{{2,}}\\b", "<user>")
| where NormalizedFamilyTitle == "{safe_title}"
| project
    IncidentNumber,
    IncidentName,
    Title,
    Severity,
    Status,
    Classification,
    ClassificationReason,
    ClassificationComment,
    Owner,
    CreatedTime,
    LastModifiedTime,
    ModifiedBy,
    Labels,
    AdditionalData,
    Tasks,
    IncidentUrl
| order by CreatedTime desc
""".strip()

    exact_res = la_query(exact_kql, f"P{days_i}D")
    if not exact_res.get("ok"):
        return exact_res

    incidents = _la_first_table_dicts(exact_res["data"])
    match_mode = "exact_normalized_family_title"

    if not incidents:
        contains_kql = f"""
SecurityIncident
| where CreatedTime >= ago({days_i}d)
| where Severity !~ "Informational"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| extend NormalizedFamilyTitle = tolower(trim(@" ", tostring(Title)))
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}\\b", "<ip>")
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b[a-f0-9]{{32,64}}\\b", "<hash>")
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b[0-9a-f]{{8}}-[0-9a-f-]{{27,36}}\\b", "<guid>")
| extend NormalizedFamilyTitle = replace_regex(NormalizedFamilyTitle, @"\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{{2,}}\\b", "<user>")
| where NormalizedFamilyTitle contains "{safe_title}"
| project
    IncidentNumber,
    IncidentName,
    Title,
    Severity,
    Status,
    Classification,
    ClassificationReason,
    ClassificationComment,
    Owner,
    CreatedTime,
    LastModifiedTime,
    ModifiedBy,
    Labels,
    AdditionalData,
    Tasks,
    IncidentUrl
| order by CreatedTime desc
""".strip()

        contains_res = la_query(contains_kql, f"P{days_i}D")
        if not contains_res.get("ok"):
            return contains_res

        incidents = _la_first_table_dicts(contains_res["data"])
        match_mode = "contains_normalized_family_title"

    classification_summary: Dict[str, int] = {}
    status_summary: Dict[str, int] = {}

    for inc in incidents:
        cls = str(inc.get("Classification") or "Unclassified")
        st = str(inc.get("Status") or "Unknown")
        classification_summary[cls] = classification_summary.get(cls, 0) + 1
        status_summary[st] = status_summary.get(st, 0) + 1

    return _ok({
        "days_reviewed": days_i,
        "match_mode": match_mode,
        "normalized_title": normalized_title,
        "count": len(incidents),
        "classification_summary": classification_summary,
        "status_summary": status_summary,
        "incidents": incidents,
    })

def _risk_from_severity_and_alerts(severity: str, alert_count: int, entity_count: int) -> Tuple[str, int]:
    sev = (severity or "").lower()
    score = 0
    if sev == "high":
        score += 4
    elif sev == "medium":
        score += 2
    else:
        score += 1

    if alert_count > 5:
        score += 2
    elif alert_count > 1:
        score += 1

    if entity_count > 3:
        score += 1

    if score >= 6:
        return "High", score
    if score >= 3:
        return "Medium", score
    return "Low", score

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
    "lookup_cmdb_entity",
    "Performs a direct CMDB lookup in COVERAGE_CMDB for a host, IP, FQDN, domain, or infrastructure identifier.",
    {
        "value": "Entity value to search in CMDB",
        "timespan": "ISO8601 duration like PT6H, P1D, P7D"
    }
)

@mcp.tool
def lookup_cmdb_entity(value: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    if not value:
        return _fail("value is required", code="VALIDATION_ERROR")

    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    res = _query_cmdb_entity(value, timespan)
    if not res.get("ok"):
        return res

    rows = _la_first_table_dicts(res["data"])
    return _ok({
        "value": value,
        "table": CMDB_TABLE,
        "matches": rows,
        "count": len(rows),
    }, timespan=timespan)

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
    tables_considered = [t for t, _ in queries]
    tables_checked = []
    tables_succeeded = []
    tables_failed = []
    tables_skipped_by_catalog = []

    for table, where_clause in queries:
        if preferred_tables and table not in preferred_tables:
            tables_skipped_by_catalog.append(table)
            continue

        tables_checked.append(table)

        summary_kql = f"""
{table}
| where {where_clause}
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
""".strip()

        res = la_query(summary_kql, timespan)
        if not res.get("ok"):
            tables_failed.append({
                "table": table,
                "error": res.get("error", {}),
            })
            continue

        tables_succeeded.append(table)
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

        rationale = []
        if count > 100:
            risk_score += 2
            rationale.append("high event volume")
        elif count > 20:
            risk_score += 1
            rationale.append("moderate event volume")

        if table in ["SecurityEvent", "AuditLogs", "SecurityAlert"]:
            risk_score += 1
            rationale.append("security-relevant table")

        findings.append({
            "table": table,
            "count": count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "risk_rationale": rationale,
        })

    cmdb_context = None
    cmdb_status = "not_reviewed"
    if entity_type in {"ip", "host", "domain"}:
        cmdb_res = _query_cmdb_entity(value, timespan)
        if cmdb_res.get("ok"):
            cmdb_status = "reviewed"
            cmdb_context = _la_first_table_dicts(cmdb_res["data"])
        else:
            cmdb_status = "lookup_failed"
            cmdb_context = {
                "error": cmdb_res.get("error", {})
            }

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
        "telemetry_domains_considered": preferred_domains,
        "tables_considered": tables_considered,
        "tables_checked": tables_checked,
        "tables_succeeded": tables_succeeded,
        "tables_failed": tables_failed,
        "tables_skipped_by_catalog": tables_skipped_by_catalog,
        "tables_hit": len(findings),
        "total_events": total_events,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_note": "Heuristic score based on counts and table context; not a standalone verdict.",
        "cmdb_status": cmdb_status,
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
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    top = clamp_rows(top)

    if not incident_id:
        if hours.is_integer():
            ago_expr = f"{int(hours)}h"
        else:
            ago_expr = f"{hours}h"

        kql = f"""
SecurityIncident
| where Severity !~ "Informational"
| where CreatedTime >= ago({ago_expr})
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project
    IncidentNumber,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime
| order by CreatedTime desc
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
{_sentinel_incident_latest_kql(safe_id)}
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
    by
    IncidentNumber,
    Title,
    Severity,
    Status,
    Owner,
    CreatedTime,
    LastModifiedTime,
    Classification,
    ClassificationReason,
    ClassificationComment
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
        "classification": incident.get("Classification"),
        "classification_reason": incident.get("ClassificationReason"),
        "classification_comment": incident.get("ClassificationComment"),
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
    "SOC investigation of a Microsoft Sentinel incident. Extracts alerts, evidence-backed entities, timeline, CMDB context, and coverage notes.",
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
    incident_kql = _sentinel_incident_latest_kql(safe_id)

    inc_res = la_query(incident_kql, timespan)
    if not inc_res.get("ok"):
        return inc_res

    incident_rows = _la_first_table_dicts(inc_res["data"])
    if not incident_rows:
        return _fail("Incident not found", code="NOT_FOUND")

    incident = incident_rows[0]
    alert_ids = _parse_alert_ids(incident.get("AlertIds"))

    workspace_domains = list(WORKSPACE_TABLE_CATALOG.keys()) if WORKSPACE_TABLE_CATALOG else []
    coverage_notes = {
        "catalog_loaded": bool(WORKSPACE_TABLE_CATALOG),
        "telemetry_domains_available": workspace_domains,
        "telemetry_reviewed": [],
        "telemetry_not_reviewed": [],
        "lookup_failures": [],
    }

    if not alert_ids:
        risk_level, risk_score = _risk_from_severity_and_alerts(
            incident.get("Severity", ""),
            alert_count=0,
            entity_count=0,
        )
        return _ok({
            "incident": {
                "id": incident.get("IncidentNumber"),
                "name": incident.get("IncidentName"),
                "title": incident.get("Title"),
                "severity": incident.get("Severity"),
                "status": incident.get("Status"),
                "owner": incident.get("Owner"),
                "classification": incident.get("Classification"),
                "classification_reason": incident.get("ClassificationReason"),
                "classification_comment": incident.get("ClassificationComment"),
                "created_time": incident.get("CreatedTime"),
                "last_modified_time": incident.get("LastModifiedTime"),
            },
            "alerts": {
                "count": 0,
                "details": [],
            },
            "entities": {},
            "top_pivots": [],
            "timeline": {
                "incident_created": incident.get("CreatedTime"),
                "first_alert": None,
                "last_alert": None,
            },
            "asset_context": [],
            "coverage": coverage_notes,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "assessment": "Incident has no linked alerts",
        })

    safe_alerts = [escape_kql_string(str(a)) for a in alert_ids if a]
    alert_list = ",".join([f'"{a}"' for a in safe_alerts])

    alerts_kql = f"""
SecurityAlert
| where SystemAlertId in ({alert_list})
| project
    SystemAlertId,
    AlertName = ProductName,
    Component = ProductComponentName,
    AlertTime = StartTime,
    EndTime,
    Status,
    Severity,
    CompromisedEntity,
    Tactics,
    Techniques,
    AlertLink,
    Entities
| order by AlertTime asc
""".strip()

    alert_res = la_query(alerts_kql, timespan)
    if not alert_res.get("ok"):
        return alert_res

    alerts = _la_first_table_dicts(alert_res["data"])
    coverage_notes["telemetry_reviewed"].append("alerts_and_incidents")

    entity_map = _extract_alert_entities(alerts)
    entity_count = (
        len(entity_map.get("users", []))
        + len(entity_map.get("ips", []))
        + len(entity_map.get("hosts", []))
        + len(entity_map.get("domains", []))
        + len(entity_map.get("hashes", []))
        + len(entity_map.get("urls", []))
    )

    top_pivots = _select_top_entities(entity_map, max_entities=3)

    cmdb_context = []
    for pivot in top_pivots:
        if pivot["type"] in {"ip", "host", "domain"}:
            cmdb_res = _query_cmdb_entity(str(pivot["value"]), timespan)
            if cmdb_res.get("ok"):
                coverage_notes["telemetry_reviewed"].append("cmdb_and_asset_context")
                cmdb_context.append({
                    "entity": pivot["value"],
                    "entity_type": pivot["type"],
                    "matches": _la_first_table_dicts(cmdb_res["data"]),
                })
            else:
                coverage_notes["lookup_failures"].append({
                    "lookup": "cmdb",
                    "entity": pivot["value"],
                    "error": cmdb_res.get("error", {})
                })

    alert_times = [a.get("AlertTime") for a in alerts if a.get("AlertTime")]
    first_alert = min(alert_times) if alert_times else None
    last_alert = max(alert_times) if alert_times else None

    tactics = sorted({a.get("Tactics") for a in alerts if a.get("Tactics")})
    techniques = sorted({a.get("Techniques") for a in alerts if a.get("Techniques")})

    risk_level, risk_score = _risk_from_severity_and_alerts(
        incident.get("Severity", ""),
        alert_count=len(alerts),
        entity_count=entity_count,
    )

    coverage_notes["telemetry_reviewed"] = sorted(set(coverage_notes["telemetry_reviewed"]))
    if WORKSPACE_TABLE_CATALOG:
        coverage_notes["telemetry_not_reviewed"] = sorted(
            set(WORKSPACE_TABLE_CATALOG.keys()) - set(coverage_notes["telemetry_reviewed"])
        )

    return _ok({
        "incident": {
            "id": incident.get("IncidentNumber"),
            "name": incident.get("IncidentName"),
            "title": incident.get("Title"),
            "severity": incident.get("Severity"),
            "status": incident.get("Status"),
            "owner": incident.get("Owner"),
            "classification": incident.get("Classification"),
            "classification_reason": incident.get("ClassificationReason"),
            "classification_comment": incident.get("ClassificationComment"),
            "created_time": incident.get("CreatedTime"),
            "last_modified_time": incident.get("LastModifiedTime"),
        },
        "alerts": {
            "count": len(alerts),
            "names": sorted({a.get("AlertName") for a in alerts if a.get("AlertName")}),
            "components": sorted({a.get("Component") for a in alerts if a.get("Component")}),
            "details": alerts,
        },
        "entities": entity_map,
        "top_pivots": top_pivots,
        "timeline": {
            "incident_created": incident.get("CreatedTime"),
            "incident_last_modified": incident.get("LastModifiedTime"),
            "first_alert": first_alert,
            "last_alert": last_alert,
        },
        "mitre": {
            "tactics": tactics,
            "techniques": techniques,
        },
        "asset_context": cmdb_context,
        "coverage": coverage_notes,
        "risk_level": risk_level,
        "risk_score": risk_score,
    })

_register_tool_def(
    "get_similar_incident_history",
    "Looks up incidents from the last N days with the same or similar normalized title and returns prior classifications and status history.",
    {
        "incident_id": "Sentinel incident number",
        "days": "optional integer, default 30"
    }
)

@mcp.tool
def get_similar_incident_history(incident_id: str, days: int = 30) -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        days_i = int(days)
    except Exception:
        days_i = 30

    days_i = max(1, min(days_i, 90))
    safe_id = escape_kql_string(str(incident_id).strip())

    current_kql = f"""
{_sentinel_incident_latest_kql(safe_id)}
| project IncidentNumber, IncidentName, Title, Severity, Status, CreatedTime, LastModifiedTime
""".strip()

    current_res = la_query(current_kql, f"P{days_i}D")
    if not current_res.get("ok"):
        return current_res

    current_rows = _la_first_table_dicts(current_res["data"])
    if not current_rows:
        return _fail("Incident not found", code="NOT_FOUND")

    current_incident = current_rows[0]
    title = current_incident.get("Title")

    if not title or not str(title).strip():
        return _fail("Incident title not found", code="PARSE_ERROR")

    hist_res = _similar_incident_lookup(str(title), days_i)
    if not hist_res.get("ok"):
        return hist_res

    return _ok({
        "reference_incident": {
            "incident_number": current_incident.get("IncidentNumber"),
            "incident_name": current_incident.get("IncidentName"),
            "title": current_incident.get("Title"),
            "severity": current_incident.get("Severity"),
            "status": current_incident.get("Status"),
            "created_time": current_incident.get("CreatedTime"),
            "last_modified_time": current_incident.get("LastModifiedTime"),
        },
        **hist_res["data"],
    })

_register_tool_def(
    "triage_incident",
    "Performs end-to-end incident triage: incident context, alert review, similar history, CMDB enrichment, and top entity pivots.",
    {
        "incident_id": "Sentinel incident number",
        "timespan": "ISO8601 duration (P1D, P7D)",
        "similar_days": "optional integer, default 30",
        "max_pivots": "optional integer, default 3"
    }
)

@mcp.tool
def triage_incident(
    incident_id: str,
    timespan: str = "P7D",
    similar_days: int = DEFAULT_SIMILAR_DAYS,
    max_pivots: int = 3,
) -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
        similar_days_i = max(1, min(int(similar_days), 90))
        max_pivots_i = max(1, min(int(max_pivots), 5))
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_INCIDENT:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_INCIDENT}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h"
        )

    inv_res = investigate_incident(incident_id=incident_id, timespan=timespan)
    if not inv_res.get("ok"):
        return inv_res

    inv = inv_res["data"]

    title = inv.get("incident", {}).get("title") or ""
    hist_res = _similar_incident_lookup(title, similar_days_i) if title else _ok({
        "days_reviewed": similar_days_i,
        "match_mode": "not_run",
        "normalized_title": "",
        "count": 0,
        "classification_summary": {},
        "status_summary": {},
        "incidents": [],
    })

    selected_pivots = inv.get("top_pivots", [])[:max_pivots_i]
    pivot_results = []
    lookup_failures = []

    for pivot in selected_pivots:
        if pivot["type"] not in {"ip", "user", "host", "domain", "sha256", "sha1", "md5"}:
            continue

        res = analyze_entity(
            value=str(pivot["value"]),
            timespan=timespan,
            max_rows=DEFAULT_ROWS
        )

        if res.get("ok"):
            pivot_results.append({
                "entity": pivot,
                "result": res["data"],
            })
        else:
            lookup_failures.append({
                "entity": pivot,
                "error": res.get("error", {}),
            })

    supporting_findings = []
    weakening_findings = []
    unresolved_gaps = []

    if hist_res.get("ok"):
        hist = hist_res["data"]
        if hist.get("count", 0) > 0:
            supporting_findings.append(
                f"Historical incidents found with similar title: {hist.get('count')}"
            )
            if hist.get("classification_summary"):
                weakening_findings.append(
                    f"Historical classifications: {hist.get('classification_summary')}"
                )
    else:
        unresolved_gaps.append("Historical incident lookup failed")

    for pr in pivot_results:
        entity_value = pr["entity"]["value"]
        entity_type = pr["entity"]["type"]
        pdata = pr["result"]

        if pdata.get("tables_hit", 0) > 0:
            supporting_findings.append(
                f"{entity_type}:{entity_value} had activity in reviewed telemetry ({pdata.get('tables_hit')} tables hit)"
            )
        else:
            weakening_findings.append(
                f"{entity_type}:{entity_value} had no hits in reviewed telemetry"
            )

        if pdata.get("tables_failed"):
            unresolved_gaps.append(
                f"{entity_type}:{entity_value} had failed lookups in some tables"
            )

    if lookup_failures:
        unresolved_gaps.append("One or more entity pivots failed")

    incident_severity = (inv.get("incident", {}).get("severity") or "").lower()
    alert_count = inv.get("alerts", {}).get("count", 0)

    verdict = "Suspicious"
    if incident_severity == "high" and (supporting_findings or alert_count > 1):
        verdict = "Clearly concerning"
    elif not supporting_findings and weakening_findings:
        verdict = "Likely benign"

    return _ok({
        "triage_verdict": verdict,
        "incident": inv.get("incident"),
        "why_incident_triggered": {
            "alert_count": inv.get("alerts", {}).get("count", 0),
            "alert_names": inv.get("alerts", {}).get("names", []),
            "alert_components": inv.get("alerts", {}).get("components", []),
            "mitre": inv.get("mitre", {}),
        },
        "entities_investigated": selected_pivots,
        "cmdb_asset_context": inv.get("asset_context", []),
        "historical_incident_context": hist_res["data"] if hist_res.get("ok") else {
            "error": hist_res.get("error", {})
        },
        "telemetry_reviewed": {
            "coverage": inv.get("coverage", {}),
            "entity_pivots": pivot_results,
        },
        "findings_supporting_suspicion": supporting_findings,
        "findings_weakening_suspicion": weakening_findings,
        "missing_evidence_or_unresolved_gaps": unresolved_gaps,
        "timeline": inv.get("timeline", {}),
        "risk_assessment": {
            "risk_level": inv.get("risk_level"),
            "risk_score": inv.get("risk_score"),
        },
        "analyst_conclusion": (
            "Verdict is based on reviewed incident context, linked alerts, selected entity pivots, "
            "CMDB enrichment where applicable, and recent similar incident history."
        ),
    })

# ============================================================
# EXPORT ASGI APP
# ============================================================

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
