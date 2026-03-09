from __future__ import annotations

from typing import Any

from ..catalog import WorkspaceCatalog
from ..clients.log_analytics import query_workspace
from ..config import Settings
from ..responses import fail, ok
from ..utils import detect_entity_type, escape_kql_string, parse_timespan_to_hours


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


def _parse_table_rows(result: dict) -> list[dict[str, Any]]:
    tables = (result.get("data") or {}).get("tables") or []
    if not tables:
        return []
    columns = [c["name"] for c in tables[0].get("columns", [])]
    return [dict(zip(columns, row)) for row in tables[0].get("rows", [])]


def investigate_entity(
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

        result = query_workspace(settings, kql, timespan)
        if not result.get("ok"):
            continue

        rows = _parse_table_rows(result)
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
        "telemetry_domains_checked": domains,
        "tables_queried": queried_tables,
        "findings": findings,
        "coverage_note": (
            "Known structured fields were queried first. "
            "Add bounded raw-field fallback only if you need deeper hunting."
        ),
    }, timespan=timespan, max_rows=max_rows)