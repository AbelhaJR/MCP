from __future__ import annotations

from ..clients.arm import arm_get
from ..config import Settings
from ..responses import fail, ok


API_VERSION = "2024-01-01-preview"


def _rules_path(settings: Settings) -> str:
    return (
        f"/subscriptions/{settings.subscription_id}"
        f"/resourceGroups/{settings.resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{settings.workspace_name}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )


def list_analytic_rules(settings: Settings, limit: int = 50) -> dict:
    result = arm_get(settings, _rules_path(settings), API_VERSION)
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


def get_analytic_rule(settings: Settings, rule_id: str) -> dict:
    if not rule_id:
        return fail("VALIDATION_ERROR", "rule_id is required")

    path = f"{_rules_path(settings)}/{rule_id}"
    result = arm_get(settings, path, API_VERSION)
    if not result.get("ok"):
        return result

    return ok({"rule": result.get("data")})
