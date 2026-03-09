from __future__ import annotations

import re

_TIMESPAN_RE = re.compile(r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?)?$", re.IGNORECASE)
_TABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def parse_timespan_to_hours(value: str) -> int:
    match = _TIMESPAN_RE.fullmatch(value.strip())
    if not match:
        raise ValueError("Timespan must be ISO8601 like PT6H, P1D, or P7D")
    days = int(match.group("days") or 0)
    hours = int(match.group("hours") or 0)
    total = days * 24 + hours
    if total <= 0:
        raise ValueError("Timespan must be greater than zero")
    return total


def clamp_rows(value: int, hard_limit: int) -> int:
    if value <= 0:
        return min(50, hard_limit)
    return min(value, hard_limit)


def validate_table_name(table: str) -> str:
    if not table or not _TABLE_RE.fullmatch(table):
        raise ValueError("Invalid table name")
    return table


def escape_kql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def ensure_take_limit(kql: str, limit: int) -> str:
    if re.search(r"\|\s*take\s+\d+", kql, flags=re.IGNORECASE):
        return kql
    return f"{kql.rstrip()}\n| take {limit}"


def kql_safety_check(kql: str) -> None:
    banned = [
        r"\.show\s+tables",
        r"\.drop\b",
        r"\.delete\b",
        r"\.alter\b",
        r"\.create\b",
        r"\.ingest\b",
    ]
    lowered = kql.lower()
    for pattern in banned:
        if re.search(pattern, lowered):
            raise ValueError(f"KQL contains blocked pattern: {pattern}")


def detect_entity_type(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return "ip"
    if "@" in value:
        return "user"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"
    if "." in value:
        return "domain"
    return "host"