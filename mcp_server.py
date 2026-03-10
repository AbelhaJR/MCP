from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from fastmcp import FastMCP


# ============================================================
# CONFIG
# ============================================================

@dataclass(frozen=True)
class Settings:
    workspace_id: str
    workspace_name: str
    subscription_id: str
    resource_group: str
    default_timespan: str
    la_http_timeout: int
    max_rows_hard: int
    max_hours_run_query: int
    max_hours_investigation: int
    enable_run_kql: bool
    catalog_path: str


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def get_settings() -> Settings:
    return Settings(
        workspace_id=os.environ.get("WORKSPACE_ID", ""),
        workspace_name=os.environ.get("WORKSPACE_NAME", ""),
        subscription_id=os.environ.get("SUBSCRIPTION_ID", ""),
        resource_group=os.environ.get("RESOURCE_GROUP", ""),
        default_timespan=os.environ.get("DEFAULT_TIMESPAN", "P3D"),
        la_http_timeout=int(os.environ.get("LA_HTTP_TIMEOUT", "20")),
        max_rows_hard=int(os.environ.get("MAX_ROWS_HARD", "200")),
        max_hours_run_query=int(os.environ.get("MAX_HOURS_RUN_QUERY", "72")),
        max_hours_investigation=int(os.environ.get("MAX_HOURS_INVESTIGATION", "168")),
        enable_run_kql=_as_bool(os.environ.get("ENABLE_RUN_KQL"), True),
        catalog_path=os.environ.get("WORKSPACE_TABLE_CATALOG_PATH", "workspace_tables.json"),
    )


def validate_required_settings(settings: Settings) -> list[str]:
    missing: list[str] = []
    if not settings.workspace_id:
        missing.append("WORKSPACE_ID")
    if not settings.workspace_name:
        missing.append("WORKSPACE_NAME")
    if not settings.subscription_id:
        missing.append("SUBSCRIPTION_ID")
    if not settings.resource_group:
        missing.append("RESOURCE_GROUP")
    return missing


# ============================================================
# RESPONSE HELPERS
# ============================================================

def ok(data: Any, **meta: Any) -> dict:
    return {
        "ok": True,
        "data": data,
        "meta": meta or {},
    }


def fail(code: str, message: str, detail: str | None = None, **meta: Any) -> dict:
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "detail": detail,
        },
        "meta": meta or {},
    }


# ============================================================
# UTILS
# ============================================================

_TIMESPAN_RE = re.compile(r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?)?$", re.IGNORECASE)
_TABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_TOKEN_CACHE: dict[str, dict[str, Any]] = {}

LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
ARM_RESOURCE = "https://management.azure.com/"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"


def parse_timespan_to_hours(value: str) -> int:
    match = _TIMESPAN_RE.fullmatch(value.strip())
    if not match:
        raise ValueError("Timespan must be ISO8601 like PT6H, P1D, or P7D")
    days = int(match.group("days") or 0)
    hours = int(match.group("hours") or 0)
    total = days * 24 + hours
    if total <= 0:
        raise ValueError("Timespan must be greater than zero")
    return total


def clamp_rows(value: int, hard_limit: int) -> int:
    if value <= 0:
        return min(50, hard_limit)
    return min(value, hard_limit)


def validate_table_name(table: str) -> str:
    if not table or not _TABLE_RE.fullmatch(table):
        raise ValueError("Invalid table name")
    return table


def escape_kql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def ensure_take_limit(kql: str, limit: int) -> str:
    if re.search(r"\|\s*take\s+\d+", kql, flags=re.IGNORECASE):
        return kql
    return f"{kql.rstrip()}\n| take {limit}"


def kql_safety_check(kql: str) -> None:
    blocked = [
        r"\.show\s+tables",
        r"\.drop\b",
        r"\.delete\b",
        r"\.alter\b",
        r"\.create\b",
        r"\.ingest\b",
    ]
    lowered = kql.lower()
    for pattern in blocked:
        if re.search(pattern, lowered):
            raise ValueError(f"KQL contains blocked pattern: {pattern}")


def detect_entity_type(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return "ip"
    if "@" in value:
        return "user"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"
    if "." in value:
        return "domain"
    return "host"


def parse_la_rows(result: dict) -> list[dict[str, Any]]:
    if not result.get("ok"):
        return []
    tables = (result.get("data") or {}).get("tables") or []
    if not tables:
        return []
    columns = [c["name"] for c in tables[0].get("columns", [])]
    return [dict(zip(columns, row)) for row in tables[0].get("rows", [])]


# ============================================================
# CATALOG
# ============================================================

class WorkspaceCatalog:
    def __init__(self, catalog_path: str):
        self.catalog_path = Path(catalog_path)
        self._data = self._load()

    def _load(self) -> dict[str, list[str]]:
        if not self.catalog_path.exists():
            return {}
        raw = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Workspace catalog must be a JSON object")
        normalized: dict[str, list[str]] = {}
        for key, value in raw.items():
            if isinstance(value, list):
                normalized[str(key)] = [str(v) for v in value if isinstance(v, str)]
        return normalized

    @property
    def data(self) -> dict[str, list[str]]:
        return self._data

    def get(self, key: str) -> list[str]:
        return list(self._data.get(key, []))

    def keys(self) -> list[str]:
        return sorted(self._data.keys())

    def search_categories(self, text: str) -> dict[str, list[str]]:
        text = text.lower().strip()
        out: dict[str, list[str]] = {}
        for key, tables in self._data.items():
            if text in key.lower() or any(text in t.lower() for t in tables):
                out[key] = tables
        return out

    def cmdb_tables(self) -> list[str]:
        for key in self._data:
            if "cmdb" in key.lower():
                return self._data[key]
        return []

    def telemetry_domains_for_entity(self, entity_type: str) -> list[str]:
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
        default_domains = ["alerts_and_incidents", "identity_and_authentication"]
        return [d for d in mapping.get(entity_type, default_domains) if d in self._data]

    def tables_for_domains(self, domains: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for domain in domains:
            for table in self._data.get(domain, []):
                if table not in seen:
                    seen.add(table)
                    out.append(table)
        return out


# ============================================================
# AUTH / HTTP CLIENTS
# ============================================================

def get_managed_identity_token(resource: str) -> str:
    now = int(time.time())
    cached = _TOKEN_CACHE.get(resource)
    if cached and cached["exp"] - now > 60:
        return cached["token"]

    response = requests.get(
        IMDS_ENDPOINT,
        params={"api-version": "2018-02-01", "resource": resource},
        headers={"Metadata": "true"},
        timeout=5,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload["access_token"]
    expires_on = int(payload.get("expires_on", now + 300))
    _TOKEN_CACHE[resource] = {"token": token, "exp": expires_on}
    return token


def la_query(settings: Settings, kql: str, timespan: str) -> dict:
    if not settings.workspace_id:
        return fail("CONFIG_ERROR", "WORKSPACE_ID is not configured")

    url = f"https://api.loganalytics.io/v1/workspaces/{settings.workspace_id}/query"
    token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"query": kql, "timespan": timespan},
        timeout=settings.la_http_timeout,
    )

    if response.status_code >= 400:
        return fail(
            "LOG_ANALYTICS_ERROR",
            f"Log Analytics query failed with HTTP {response.status_code}",
            detail=response.text[:1500],
            timespan=timespan,
        )

    try:
        return ok(response.json(), timespan=timespan)
    except Exception as exc:
        return fail("PARSE_ERROR", "Failed to parse Log Analytics response", detail=str(exc))


def arm_get(settings: Settings, path: str, api_version: str) -> dict:
    token = get_managed_identity_token(ARM_RESOURCE)
    url = f"https://management.azure.com{path}"

    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        params={"api-version": api_version},
        timeout=settings.la_http_timeout,
    )

    if response.status_code >= 400:
        return fail(
            "ARM_ERROR",
            f"ARM GET failed with HTTP {response.status_code}",
            detail=response.text[:1500],
        )

    try:
        return ok(response.json())
    except Exception as exc:
        return fail("PARSE_ERROR", "Failed to parse ARM response", detail=str(exc))


# ============================================================
# SERVICE: SCHEMA / TABLES
# ============================================================

def service_get_workspace_catalog(catalog: WorkspaceCatalog) -> dict:
    return ok({"catalog": catalog.data})


def service_preview_table(settings: Settings, table: str, timespan: str) -> dict:
    try:
        table = validate_table_name(table)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))
    return la_query(settings, f"{table}\n| take 10", timespan)


def service_get_table_schema(settings: Settings, table: str, timespan: str) -> dict:
    try:
        table = validate_table_name(table)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))
    return la_query(settings, f"{table}\n| getschema", timespan)


# ============================================================
# SERVICE: CMDB
# ============================================================

def service_enrich_asset(settings: Settings, catalog: WorkspaceCatalog, value: str, timespan: str) -> dict:
    cmdb_tables = catalog.cmdb_tables()
    if not cmdb_tables:
        return ok({
            "entity": value,
            "asset_context": [],
            "message": "No CMDB table category is configured in the workspace catalog.",
        })

    table = cmdb_tables[0]
    safe_value = escape_kql_string(value)

    kql = f"""
{table}
| where tostring(Management_IP) contains "{safe_value}"
    or tostring(FQDN) contains "{safe_value}"
    or tostring(Key) contains "{safe_value}"
    or tostring(Network_Interfaces) contains "{safe_value}"
    or tostring(logsource) contains "{safe_value}"
| take 10
""".strip()

    result = la_query(settings, kql, timespan)
    if not result.get("ok"):
        return result

    return ok({
        "entity": value,
        "cmdb_table": table,
        "asset_context": result.get("data"),
    })


# ============================================================
# SERVICE: ENTITY INVESTIGATION
# ============================================================

ENTITY_FIELD_MAP: dict[str, list[tuple[str, str]]] = {
    "ip": [
        ("SigninLogs", 'IPAddress == "{value}"'),
        ("SecurityAlert", 'CompromisedEntity contains "{value}" or tostring(Entities) contains "{value}"'),
        ("DeviceNetworkEvents", 'RemoteIP == "{value}" or LocalIP == "{value}"'),
        ("AzureActivity", 'CallerIpAddress == "{value}"'),
    ],
    "user": [
        ("SigninLogs", 'UserPrincipalName =~ "{value}"'),
        ("IdentityLogonEvents", 'AccountUpn =~ "{value}" or AccountName =~ "{value}"'),
        ("DeviceLogonEvents", 'AccountName =~ "{value}" or InitiatingProcessAccountUpn =~ "{value}"'),
        ("OfficeActivity", 'UserId =~ "{value}"'),
    ],
    "host": [
        ("DeviceInfo", 'DeviceName =~ "{value}"'),
        ("DeviceEvents", 'DeviceName =~ "{value}"'),
        ("DeviceProcessEvents", 'DeviceName =~ "{value}"'),
        ("SecurityAlert", 'CompromisedEntity contains "{value}" or tostring(Entities) contains "{value}"'),
    ],
    "domain": [
        ("DeviceNetworkEvents", 'RemoteUrl contains "{value}"'),
        ("UrlClickEvents", 'Url contains "{value}"'),
        ("EmailUrlInfo", 'Url contains "{value}"'),
    ],
    "sha256": [
        ("DeviceFileEvents", 'SHA256 == "{value}"'),
    ],
    "sha1": [
        ("DeviceFileEvents", 'SHA1 == "{value}"'),
    ],
    "md5": [
        ("DeviceFileEvents", 'MD5 == "{value}"'),
    ],
}


def service_investigate_entity(
    settings: Settings,
    catalog: WorkspaceCatalog,
    value: str,
    timespan: str,
    max_rows: int,
) -> dict:
    if not value:
        return fail("VALIDATION_ERROR", "value is required")

    try:
        hours = parse_timespan_to_hours(timespan)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))

    if hours > settings.max_hours_investigation:
        return fail(
            "VALIDATION_ERROR",
            f"timespan exceeds allowed window ({settings.max_hours_investigation}h max)",
        )

    entity_type = detect_entity_type(value)
    safe_value = escape_kql_string(value)
    domains = catalog.telemetry_domains_for_entity(entity_type)
    preferred_tables = catalog.tables_for_domains(domains)
    field_map = ENTITY_FIELD_MAP.get(entity_type, [])

    findings: list[dict[str, Any]] = []
    queried_tables: list[str] = []

    cmdb_context = None
    if entity_type in {"ip", "host", "domain"}:
        cmdb_context = service_enrich_asset(settings, catalog, value, timespan)

    for table_name, where_template in field_map:
        if table_name not in preferred_tables:
            continue

        queried_tables.append(table_name)
        where_clause = where_template.format(value=safe_value)
        kql = f"""
{table_name}
| where {where_clause}
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
""".strip()

        result = la_query(settings, kql, timespan)
        if not result.get("ok"):
            continue

        rows = parse_la_rows(result)
        if not rows:
            continue

        row = rows[0]
        count = int(row.get("Count", 0) or 0)
        if count <= 0:
            continue

        domain = next((d for d in domains if table_name in catalog.get(d)), "unknown")
        findings.append({
            "table": table_name,
            "telemetry_domain": domain,
            "matched_entity": value,
            "summary": f"Matched {value} in {table_name}",
            "count": count,
            "first_seen": row.get("FirstSeen"),
            "last_seen": row.get("LastSeen"),
        })

    return ok({
        "entity": value,
        "entity_type": entity_type,
        "cmdb_context": cmdb_context["data"] if isinstance(cmdb_context, dict) and cmdb_context.get("ok") else None,
        "telemetry_domains_checked": domains,
        "tables_queried": queried_tables,
        "findings": findings,
        "coverage_note": (
            "Known structured fields were queried first. "
            "Add bounded raw-field fallback only if needed."
        ),
    }, timespan=timespan, max_rows=max_rows)


# ============================================================
# SERVICE: INCIDENT INVESTIGATION
# ============================================================

def _extract_entities_from_alerts(alert_rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    users: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    domains: set[str] = set()

    for alert in alert_rows:
        raw_entities = alert.get("Entities")
        if not raw_entities:
            continue

        try:
            entities = json.loads(raw_entities) if isinstance(raw_entities, str) else raw_entities
        except Exception:
            continue

        if not isinstance(entities, list):
            continue

        for entity in entities:
            if not isinstance(entity, dict):
                continue

            etype = (entity.get("Type") or "").lower()
            if etype == "account":
                name = entity.get("Name") or entity.get("UPNSuffix")
                if name:
                    users.add(str(name))
            elif etype == "ip":
                address = entity.get("Address")
                if address:
                    ips.add(str(address))
            elif etype in {"host", "machine"}:
                hostname = entity.get("HostName")
                if hostname:
                    hosts.add(str(hostname))
            elif etype == "dns":
                domain = entity.get("DomainName")
                if domain:
                    domains.add(str(domain))

    return {
        "users": sorted(users),
        "ips": sorted(ips),
        "hosts": sorted(hosts),
        "domains": sorted(domains),
    }


def _risk_classification(incident: dict[str, Any], alerts: list[dict[str, Any]], entities: dict[str, list[str]]) -> dict:
    score = 0
    rationale: list[str] = []

    severity = (incident.get("Severity") or "").lower()
    if severity == "high":
        score += 4
        rationale.append("Incident severity is High.")
    elif severity == "medium":
        score += 2
        rationale.append("Incident severity is Medium.")
    else:
        score += 1
        rationale.append("Incident severity is Low or unspecified.")

    if len(alerts) >= 5:
        score += 2
        rationale.append("Incident has 5 or more linked alerts.")
    if entities.get("ips"):
        score += 1
        rationale.append("Incident includes IP entities.")
    if entities.get("hosts"):
        score += 1
        rationale.append("Incident includes host entities.")
    if entities.get("users"):
        score += 1
        rationale.append("Incident includes user entities.")

    if score >= 6:
        classification = "High"
    elif score >= 3:
        classification = "Medium"
    else:
        classification = "Low"

    return {"classification": classification, "rationale": rationale}


def service_investigate_incident(settings: Settings, catalog: WorkspaceCatalog, incident_id: int, timespan: str) -> dict:
    try:
        hours = parse_timespan_to_hours(timespan)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))

    if hours > settings.max_hours_investigation:
        return fail(
            "VALIDATION_ERROR",
            f"timespan exceeds allowed window ({settings.max_hours_investigation}h max)",
        )

    incident_kql = f"""
SecurityIncident
| where IncidentNumber == {incident_id}
| where Severity !~ "Informational"
| project IncidentNumber, Title, Severity, Status, Owner, CreatedTime, LastModifiedTime, AlertIds
""".strip()

    incident_result = la_query(settings, incident_kql, timespan)
    if not incident_result.get("ok"):
        return incident_result

    incident_rows = parse_la_rows(incident_result)
    if not incident_rows:
        return fail("NOT_FOUND", f"Incident {incident_id} was not found")

    incident = incident_rows[0]
    alert_ids = incident.get("AlertIds") or []
    if isinstance(alert_ids, str):
        try:
            alert_ids = json.loads(alert_ids)
        except Exception:
            alert_ids = []

    alerts: list[dict[str, Any]] = []
    if alert_ids:
        safe_ids = ",".join([f'"{escape_kql_string(str(a))}"' for a in alert_ids])
        alerts_kql = f"""
SecurityAlert
| where SystemAlertId in ({safe_ids})
| project AlertName=ProductName, Component=ProductComponentName, AlertTime=StartTime, Status, CompromisedEntity, Tactics, Techniques, Entities
""".strip()

        alert_result = la_query(settings, alerts_kql, timespan)
        if alert_result.get("ok"):
            alerts = parse_la_rows(alert_result)

    entities = _extract_entities_from_alerts(alerts)

    cmdb_context: list[dict[str, Any]] = []
    for pivot in entities["ips"][:3] + entities["hosts"][:3] + entities["domains"][:3]:
        cmdb_result = service_enrich_asset(settings, catalog, pivot, timespan)
        if cmdb_result.get("ok"):
            cmdb_context.append(cmdb_result["data"])

    alert_times = [a.get("AlertTime") for a in alerts if a.get("AlertTime")]
    tactics = sorted({a.get("Tactics") for a in alerts if a.get("Tactics")})
    techniques = sorted({a.get("Techniques") for a in alerts if a.get("Techniques")})
    risk = _risk_classification(incident, alerts, entities)

    return ok({
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
        "entities": entities,
        "timeline": {
            "first_alert": min(alert_times) if alert_times else None,
            "last_alert": max(alert_times) if alert_times else None,
        },
        "mitre": {
            "tactics": tactics,
            "techniques": techniques,
        },
        "asset_context": cmdb_context,
        "telemetry_domains_checked": [
            "alerts_and_incidents",
            "cmdb_and_asset_context",
        ],
        "risk": risk,
        "recommended_next_steps": [
            "Validate the most suspicious entities across identity, endpoint, and network telemetry.",
            "Review linked alerts for repeated indicators and pivot from confirmed entities only.",
            "Escalate if critical assets or privileged accounts are involved.",
        ],
    }, timespan=timespan)


# ============================================================
# SERVICE: ANALYTIC RULES
# ============================================================

ANALYTICS_API_VERSION = "2024-01-01-preview"


def _rules_path(settings: Settings) -> str:
    return (
        f"/subscriptions/{settings.subscription_id}"
        f"/resourceGroups/{settings.resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{settings.workspace_name}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )


def service_list_analytic_rules(settings: Settings, limit: int = 50) -> dict:
    result = arm_get(settings, _rules_path(settings), ANALYTICS_API_VERSION)
    if not result.get("ok"):
        return result

    value = (result.get("data") or {}).get("value") or []
    out = []
    for item in value[:limit]:
        props = item.get("properties") or {}
        if props.get("kind") != "Scheduled":
            continue
        out.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "display_name": props.get("displayName"),
            "severity": props.get("severity"),
            "enabled": props.get("enabled"),
            "query_frequency": props.get("queryFrequency"),
            "query_period": props.get("queryPeriod"),
        })

    return ok({"rules": out})


def service_get_analytic_rule(settings: Settings, rule_id: str) -> dict:
    if not rule_id:
        return fail("VALIDATION_ERROR", "rule_id is required")

    path = f"{_rules_path(settings)}/{rule_id}"
    result = arm_get(settings, path, ANALYTICS_API_VERSION)
    if not result.get("ok"):
        return result
    return ok({"rule": result.get("data")})


def _extract_tables_from_kql(kql: str) -> list[str]:
    if not kql:
        return []
    candidates = re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\s*\|", kql)
    seen: set[str] = set()
    tables: list[str] = []
    for name in candidates:
        if name not in seen:
            seen.add(name)
            tables.append(name)
    return tables


def _extract_ops_from_kql(kql: str) -> list[str]:
    if not kql:
        return []
    ops = [
        "where", "summarize", "join", "extend", "project",
        "project-away", "parse", "mv-expand", "evaluate",
        "union", "lookup", "distinct",
    ]
    lowered = kql.lower()
    return [op for op in ops if re.search(rf"\b{re.escape(op)}\b", lowered)]


def service_generate_use_case_document(settings: Settings, rule_id: str) -> dict:
    rule_result = service_get_analytic_rule(settings, rule_id)
    if not rule_result.get("ok"):
        return rule_result

    rule = (rule_result.get("data") or {}).get("rule") or {}
    props = rule.get("properties") or {}
    query = props.get("query") or ""

    return ok({
        "rule_name": props.get("displayName"),
        "severity": props.get("severity"),
        "description": props.get("description"),
        "query_frequency": props.get("queryFrequency"),
        "query_period": props.get("queryPeriod"),
        "tactics": props.get("tactics") or [],
        "techniques": props.get("techniques") or [],
        "tables": _extract_tables_from_kql(query),
        "operators": _extract_ops_from_kql(query),
        "query": query,
    })


# ============================================================
# SERVICE: RAW KQL
# ============================================================

def service_run_kql(settings: Settings, kql: str, timespan: str, max_rows: int) -> dict:
    if not settings.enable_run_kql:
        return fail("FEATURE_DISABLED", "run_kql is disabled")

    if not kql or not isinstance(kql, str):
        return fail("VALIDATION_ERROR", "kql is required")

    try:
        kql_safety_check(kql)
        hours = parse_timespan_to_hours(timespan)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))

    if hours > settings.max_hours_run_query:
        return fail(
            "VALIDATION_ERROR",
            f"timespan exceeds allowed window ({settings.max_hours_run_query}h max)",
        )

    bounded = ensure_take_limit(kql, clamp_rows(max_rows, settings.max_rows_hard))
    return la_query(settings, bounded, timespan)


# ============================================================
# MCP APP
# ============================================================

settings = get_settings()
catalog = WorkspaceCatalog(settings.catalog_path)
mcp = FastMCP("SentinelMCPEnterprise")
_TOOL_DEFS: list[dict[str, Any]] = []


@mcp.tool
def ping() -> dict:
    """Simple MCP health check."""
    return ok({
        "message": "pong",
        "workspace_configured": bool(settings.workspace_id),
        "catalog_loaded": bool(catalog.data),
        "missing_settings": validate_required_settings(settings),
        "mcp_path": "/mcp",
    })


_TOOL_DEFS.append({
    "name": "ping",
    "description": "Connectivity and configuration health check.",
    "params": {},
})


@mcp.tool
def get_tools() -> dict:
    """Returns the exact MCP tool list and parameter formats."""
    return ok({"tools": _TOOL_DEFS, "mcp_path": "/mcp"})


_TOOL_DEFS.append({
    "name": "get_tools",
    "description": "Returns the exact MCP tool list and parameter formats.",
    "params": {},
})


@mcp.tool
def get_workspace_catalog() -> dict:
    """Return the authoritative workspace table catalog grouped by telemetry type."""
    return service_get_workspace_catalog(catalog)


_TOOL_DEFS.append({
    "name": "get_workspace_catalog",
    "description": "Returns the authoritative workspace table catalog grouped by telemetry type.",
    "params": {},
})


@mcp.tool
def preview_table(table: str, timespan: str = settings.default_timespan) -> dict:
    """Preview 10 rows from a table."""
    return service_preview_table(settings, table, timespan)


_TOOL_DEFS.append({
    "name": "preview_table",
    "description": "Preview 10 rows from a table. Use for troubleshooting or field inspection.",
    "params": {"table": "Table name", "timespan": "ISO8601 duration"},
})


@mcp.tool
def get_table_schema(table: str, timespan: str = settings.default_timespan) -> dict:
    """Get schema for a table before writing KQL against it."""
    return service_get_table_schema(settings, table, timespan)


_TOOL_DEFS.append({
    "name": "get_table_schema",
    "description": "Returns the schema for a table. Use before querying unknown tables.",
    "params": {"table": "Table name", "timespan": "ISO8601 duration"},
})


@mcp.tool
def investigate_incident(incident_id: int, timespan: str = "P7D") -> dict:
    """
    Full Sentinel incident investigation.
    Retrieves incident details, linked alerts, entities, CMDB context, timeline, and risk.
    """
    return service_investigate_incident(settings, catalog, incident_id, timespan)


_TOOL_DEFS.append({
    "name": "investigate_incident",
    "description": "Use for a full Sentinel incident investigation. Best for incident number-led workflows.",
    "params": {"incident_id": "Sentinel incident number", "timespan": "ISO8601 duration"},
})


@mcp.tool
def investigate_entity(value: str, timespan: str = "P3D", max_rows: int = 50) -> dict:
    """
    Structured entity investigation across telemetry domains selected from the workspace catalog.
    """
    return service_investigate_entity(settings, catalog, value, timespan, max_rows)


_TOOL_DEFS.append({
    "name": "investigate_entity",
    "description": "Use for IP, hostname, user, domain, or hash investigations across relevant telemetry domains.",
    "params": {"value": "Entity value", "timespan": "ISO8601 duration", "max_rows": "Integer <= hard limit"},
})


@mcp.tool
def list_analytic_rules(limit: int = 50) -> dict:
    """List Microsoft Sentinel scheduled analytic rules."""
    return service_list_analytic_rules(settings, limit)


_TOOL_DEFS.append({
    "name": "list_analytic_rules",
    "description": "Lists Microsoft Sentinel scheduled analytic rules.",
    "params": {"limit": "Maximum number of rules to return"},
})


@mcp.tool
def get_analytic_rule(rule_id: str) -> dict:
    """Get a specific analytic rule by ARM rule name/id segment."""
    return service_get_analytic_rule(settings, rule_id)


_TOOL_DEFS.append({
    "name": "get_analytic_rule",
    "description": "Returns a specific Microsoft Sentinel analytic rule.",
    "params": {"rule_id": "Rule ARM name/id segment"},
})


@mcp.tool
def generate_use_case_document(rule_id: str) -> dict:
    """Generate a structured use-case document from a Sentinel analytic rule."""
    return service_generate_use_case_document(settings, rule_id)


_TOOL_DEFS.append({
    "name": "generate_use_case_document",
    "description": "Generates a use-case style document from an analytic rule.",
    "params": {"rule_id": "Rule ARM name/id segment"},
})


@mcp.tool
def run_kql(kql: str, timespan: str = "P1D", max_rows: int = 50) -> dict:
    """
    Expert KQL fallback tool.
    Use only when a structured tool cannot answer the question.
    """
    return service_run_kql(settings, kql, timespan, max_rows)


_TOOL_DEFS.append({
    "name": "run_kql",
    "description": "Expert fallback for bounded KQL execution. Prefer structured tools first.",
    "params": {"kql": "KQL string", "timespan": "ISO8601 duration", "max_rows": "Integer <= hard limit"},
})


asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
