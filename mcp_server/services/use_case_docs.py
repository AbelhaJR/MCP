from __future__ import annotations

import re

from ..responses import ok


def _extract_tables_from_kql(kql: str) -> list[str]:
    if not kql:
        return []
    candidates = re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\s*\|", kql)
    seen: set[str] = set()
    tables: list[str] = []
    for name in candidates:
        if name not in seen:
            seen.add(name)
            tables.append(name)
    return tables


def _extract_ops_from_kql(kql: str) -> list[str]:
    if not kql:
        return []
    ops = [
        "where", "summarize", "join", "extend", "project",
        "project-away", "parse", "mv-expand", "evaluate",
        "union", "lookup", "distinct",
    ]
    lowered = kql.lower()
    return [op for op in ops if re.search(rf"\b{re.escape(op)}\b", lowered)]


def generate_use_case_doc(rule: dict) -> dict:
    props = (rule or {}).get("properties") or {}
    query = props.get("query") or ""
    tables = _extract_tables_from_kql(query)

    document = {
        "rule_name": props.get("displayName"),
        "severity": props.get("severity"),
        "description": props.get("description"),
        "query_frequency": props.get("queryFrequency"),
        "query_period": props.get("queryPeriod"),
        "tactics": props.get("tactics") or [],
        "techniques": props.get("techniques") or [],
        "tables": tables,
        "operators": _extract_ops_from_kql(query),
        "query": query,
    }
    return ok(document)