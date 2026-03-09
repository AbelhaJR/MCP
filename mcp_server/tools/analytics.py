from __future__ import annotations

from ..config import Settings
from ..services.analytics_rules import get_analytic_rule as rule_getter
from ..services.analytics_rules import list_analytic_rules as rules_lister
from ..services.use_case_docs import generate_use_case_doc


def register_analytics_tools(mcp, settings: Settings) -> list[dict]:
    defs: list[dict] = []

    @mcp.tool
    def list_analytic_rules(limit: int = 50) -> dict:
        """List Microsoft Sentinel scheduled analytic rules."""
        return rules_lister(settings, limit)

    defs.append({
        "name": "list_analytic_rules",
        "description": "Lists Microsoft Sentinel scheduled analytic rules.",
        "params": {"limit": "Maximum number of rules to return"},
    })

    @mcp.tool
    def get_analytic_rule(rule_id: str) -> dict:
        """Get a specific analytic rule by ARM rule name/id segment."""
        return rule_getter(settings, rule_id)

    defs.append({
        "name": "get_analytic_rule",
        "description": "Returns a specific Microsoft Sentinel analytic rule.",
        "params": {"rule_id": "Rule ARM name/id segment"},
    })

    @mcp.tool
    def generate_use_case_document(rule_id: str) -> dict:
        """Generate a structured use-case document from a Sentinel analytic rule."""
        rule_result = rule_getter(settings, rule_id)
        if not rule_result.get("ok"):
            return rule_result
        rule = (rule_result.get("data") or {}).get("rule") or {}
        return generate_use_case_doc(rule)

    defs.append({
        "name": "generate_use_case_document",
        "description": "Generates a use-case style document from an analytic rule.",
        "params": {"rule_id": "Rule ARM name/id segment"},
    })

    return defs