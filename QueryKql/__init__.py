import json
import os
import re
import urllib.request
import urllib.error

import azure.functions as func
from azure.identity import DefaultAzureCredential

LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"

MAX_ROWS = 200
DEFAULT_ROWS = 50
MAX_HOURS = 24


def parse_timespan_to_hours(timespan: str) -> float:
    if not isinstance(timespan, str):
        raise ValueError("timespan must be a string")

    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan)
    if m:
        h = int(m.group(1) or 0)
        mins = int(m.group(2) or 0)
        return h + mins / 60

    d = re.fullmatch(r"P(\d+)D", timespan)
    if d:
        return int(d.group(1)) * 24

    raise ValueError("timespan must be PT#M, PT#H, or P#D")


def kql_safety_check(kql: str):
    lowered = kql.lower()

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' is not allowed")

    blocked = [
        "externaldata",
        "evaluate",
        "make-series",
        "mv-expand"
    ]

    for b in blocked:
        if b in lowered:
            raise ValueError(f"KQL contains blocked operator: {b}")


def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = kql.lower()
    if " take " in lowered or " limit " in lowered:
        return kql
    return f"{kql}\n| take {limit}"


def query_log_analytics(workspace_id, kql, timespan):
    credential = DefaultAzureCredential()
    token = credential.get_token(LOG_ANALYTICS_SCOPE).token

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = {
        "query": kql,
        "timespan": timespan
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        workspace_id = os.environ.get("WORKSPACE_ID")
        if not workspace_id:
            return func.HttpResponse(
                json.dumps({"error": "WORKSPACE_ID app setting not configured"}),
                status_code=500,
                mimetype="application/json"
            )

        body = req.get_json()
        kql = body.get("kql")
        timespan = body.get("timespan", "PT1H")
        max_rows = int(body.get("max_rows", DEFAULT_ROWS))

        if not kql:
            return func.HttpResponse(
                json.dumps({"error": "Missing 'kql' in request body"}),
                status_code=400,
                mimetype="application/json"
            )

        max_rows = max(1, min(max_rows, MAX_ROWS))
        hours = parse_timespan_to_hours(timespan)

        if hours <= 0 or hours > MAX_HOURS:
            raise ValueError("timespan exceeds allowed limit (max 24h)")

        kql_safety_check(kql)
        kql = ensure_take_limit(kql, max_rows)

        data = query_log_analytics(workspace_id, kql, timespan)

        result = {
            "meta": {
                "timespan": timespan,
                "max_rows": max_rows,
                "note": "Results are bounded for Copilot-safe execution"
            },
            "data": data
        }

        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )

    except urllib.error.HTTPError as e:
        return func.HttpResponse(
            e.read().decode("utf-8"),
            status_code=e.code,
            mimetype="application/json"
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
