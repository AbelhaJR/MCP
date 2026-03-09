from __future__ import annotations

from ..clients.log_analytics import query_workspace
from ..config import Settings
from ..responses import fail
from ..utils import clamp_rows, ensure_take_limit, kql_safety_check, parse_timespan_to_hours


def register_query_tools(mcp, settings: Settings) -> list[dict]:
    defs: list[dict] = []

    @mcp.tool
    def run_kql(kql: str, timespan: str = "P1D", max_rows: int = 50) -> dict:
        """
        Expert KQL fallback tool.
        Use only when a structured tool cannot answer the question.
        """
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
        return query_workspace(settings, bounded, timespan)

    defs.append({
        "name": "run_kql",
        "description": "Expert fallback for bounded KQL execution. Prefer structured tools first.",
        "params": {"kql": "KQL string", "timespan": "ISO8601 duration", "max_rows": "Integer <= hard limit"},
    })

    return defs