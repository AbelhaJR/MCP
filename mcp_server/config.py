from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    workspace_id: str
    workspace_name: str
    subscription_id: str
    resource_group: str
    default_timespan: str = "P3D"
    la_http_timeout: int = 20
    max_rows_hard: int = 200
    max_hours_run_query: int = 72
    max_hours_investigation: int = 168
    enable_run_kql: bool = True
    catalog_path: str = "workspace_tables.json"


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