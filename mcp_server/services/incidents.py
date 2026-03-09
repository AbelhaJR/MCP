from __future__ import annotations

import json
from typing import Any

from ..catalog import WorkspaceCatalog
from ..clients.log_analytics import query_workspace
from ..config import Settings
from ..responses import fail, ok
from ..services.cmdb import enrich_asset
from ..utils import escape_kql_string, parse_timespan_to_hours


def _parse_rows(result: dict) -> list[dict[str, Any]]:
    tables = (result.get("data") or {}).get("tables") or []
    if not tables:
        return []
    columns = [c["name"] for c in tables[0].get("columns", [])]
    return [dict(zip(columns, row)) for row in tables[0].get("rows", [])]


def _extract_entities(alert_rows: list[dict[str, Any]]) -> dict[str, list[str]]:
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


def investigate_incident(settings: Settings, catalog: WorkspaceCatalog, incident_id: int, timespan: str) -> dict:
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

    incident_result = query_workspace(settings, incident_kql, timespan)
    if not incident_result.get("ok"):
        return incident_result

    incident_rows = _parse_rows(incident_result)
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

        alert_result = query_workspace(settings, alerts_kql, timespan)
        if alert_result.get("ok"):
            alerts = _parse_rows(alert_result)

    entities = _extract_entities(alerts)

    cmdb_context: list[dict[str, Any]] = []
    for pivot in entities["ips"][:3] + entities["hosts"][:3] + entities["domains"][:3]:
        cmdb_result = enrich_asset(settings, catalog, pivot, timespan)
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