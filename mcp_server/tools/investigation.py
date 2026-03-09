from __future__ import annotations

from ..catalog import WorkspaceCatalog
from ..config import Settings
from ..services.entities import investigate_entity as entity_service
from ..services.incidents import investigate_incident as incident_service


def register_investigation_tools(mcp, settings: Settings, catalog: WorkspaceCatalog) -> list[dict]:
    defs: list[dict] = []

    @mcp.tool
    def investigate_incident(incident_id: int, timespan: str = "P7D") -> dict:
        """
        Full Sentinel incident investigation.
        Retrieves incident details, linked alerts, entities, CMDB context, timeline, and risk.
        """
        return incident_service(settings, catalog, incident_id, timespan)

    defs.append({
        "name": "investigate_incident",
        "description": "Use for a full Sentinel incident investigation. Best for incident number-led workflows.",
        "params": {"incident_id": "Sentinel incident number", "timespan": "ISO8601 duration"},
    })

    @mcp.tool
    def investigate_entity(value: str, timespan: str = "P3D", max_rows: int = 50) -> dict:
        """
        Structured entity investigation across telemetry domains selected from the workspace catalog.
        """
        return entity_service(settings, catalog, value, timespan, max_rows)

    defs.append({
        "name": "investigate_entity",
        "description": "Use for IP, hostname, user, domain, or hash investigations across relevant telemetry domains.",
        "params": {"value": "Entity value", "timespan": "ISO8601 duration", "max_rows": "Integer <= hard limit"},
    })

    return defs