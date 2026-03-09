from __future__ import annotations

from ..catalog import WorkspaceCatalog
from ..clients.log_analytics import query_workspace
from ..config import Settings
from ..responses import ok
from ..utils import escape_kql_string


def enrich_asset(settings: Settings, catalog: WorkspaceCatalog, value: str, timespan: str) -> dict:
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

    result = query_workspace(settings, kql, timespan)
    if not result.get("ok"):
        return result

    return ok({
        "entity": value,
        "cmdb_table": table,
        "asset_context": result["data"],
    })