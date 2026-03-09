from __future__ import annotations

from ..clients.log_analytics import query_workspace
from ..config import Settings
from ..responses import fail
from ..utils import validate_table_name


def preview_table(settings: Settings, table: str, timespan: str) -> dict:
    try:
        table = validate_table_name(table)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))
    return query_workspace(settings, f"{table}\n| take 10", timespan)


def get_table_schema(settings: Settings, table: str, timespan: str) -> dict:
    try:
        table = validate_table_name(table)
    except ValueError as exc:
        return fail("VALIDATION_ERROR", str(exc))
    return query_workspace(settings, f"{table}\n| getschema", timespan)