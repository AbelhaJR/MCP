from __future__ import annotations

from ..catalog import WorkspaceCatalog
from ..config import Settings
from ..responses import ok
from ..services.schema import get_table_schema as schema_getter
from ..services.schema import preview_table as preview_getter


def register_catalog_tools(mcp, settings: Settings, catalog: WorkspaceCatalog) -> list[dict]:
    defs: list[dict] = []

    @mcp.tool
    def get_workspace_catalog() -> dict:
        """Return the authoritative workspace table catalog grouped by telemetry type."""
        return ok({"catalog": catalog.data})

    defs.append({
        "name": "get_workspace_catalog",
        "description": "Returns the authoritative workspace table catalog grouped by telemetry type.",
        "params": {},
    })

    @mcp.tool
    def preview_table(table: str, timespan: str = settings.default_timespan) -> dict:
        """Preview 10 rows from a table."""
        return preview_getter(settings, table, timespan)

    defs.append({
        "name": "preview_table",
        "description": "Preview 10 rows from a table. Use for troubleshooting or field inspection.",
        "params": {"table": "Table name", "timespan": "ISO8601 duration"},
    })

    @mcp.tool
    def get_table_schema(table: str, timespan: str = settings.default_timespan) -> dict:
        """Get schema for a table before writing KQL against it."""
        return schema_getter(settings, table, timespan)

    defs.append({
        "name": "get_table_schema",
        "description": "Returns the schema for a table. Use before querying unknown tables.",
        "params": {"table": "Table name", "timespan": "ISO8601 duration"},
    })

    return defs