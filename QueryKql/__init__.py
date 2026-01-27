import json
import os
import re
from datetime import timedelta

import azure.functions as func
import requests
from azure.identity import DefaultAzureCredential

LOGANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
MAX_ROWS = 200
DEFAULT_ROWS = 50

# We’ll allow only these ISO 8601 timespans: PT#M / PT#H / P#D
# and cap to 24h.
def parse_timespan_to_hours(timespan: str) -> float:
    # Examples: PT15M, PT1H, P1D
    if not isinstance(timespan, str):
        raise ValueError("timespan must be a string")

    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", timespan)
    if m:
        h = int(m.group(1) or 0)
        mins = int(m.group(2) or 0)
        return h + mins / 60.0

    d = re.fullmatch(r"P(\d+)D", timespan)
    if d:
        days = int(d.group(1))
        return days * 24.0

    raise ValueError("timespan must be PT#M, PT#H, or P#D (e.g., PT15M, PT1H, P1D)")

def kql_basic_safety_check(kql: str) -> None:
    # This is intentionally simple. You can tighten later.
    # Prevent obvious “dump everything” patterns.
    lowered = kql.lower()

    # discourage querying *everything* without filters
    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' is not allowed.")

    # disallow external data / risky functions (adjust to your policy)
    blocked = [
        "externaldata",
        "evaluate",
        "make-series",  # can explode payloads
        "mv-expand",    # can explode payloads
    ]
    for b in blocked:
        if b in lowered:
            raise ValueError(f"KQL contains blocked operator/function: {b}")

def ensure_take_limit(kql: str, row_limit: int) -> str:
    # If user didn't include a take/limit, append a take.
    lowered = kql.lower()
    if "| take" in lowered or "| limit" in lowered or " take " in lowered or " limit " in lowered:
        return kql
    return f"{kql}\n| take {row_limit}"

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        workspace_id = os.environ.get("WORKSPACE_ID")
        if not workspace_id:
            return func.HttpResponse(
                json.dumps({"error": "Missing WORKSPACE_ID app setting"}),
                status_code=500,
                mimetype="application/json"
            )

        body = req.get_json()
        kql = body.get("kql")
        timespan = body.get("timespan", "PT1H")
        row_limit = int(body.get("max_rows", DEFAULT_ROWS))

        if not kql or not isinstance(kql, str):
            return func.HttpResponse(
                json.dumps({"error": "Provide JSON body with string field 'kql'"}),
                status_code=400,
                mimetype="application/json"
            )

        # Bound and validate inputs
        row_limit = max(1, min(row_limit, MAX_ROWS))
        hours = parse_timespan_to_hours(timespan)
        if hours <= 0:
            raise ValueError("timespan must be > 0")
        if hours > 24:
            raise ValueError("timespan too large; max is 24 hours (P1D)")

        kql_basic_safety_check(kql)
        kql = ensure_take_limit(kql, row_limit)

        # Token via Managed Identity in Azure (or dev identity locally)
        credential = DefaultAzureCredential()
        token = credential.get_token(LOGANALYTICS_SCOPE).token

        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        payload = {"query": kql, "timespan": timespan}
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)

        # If Log Analytics errors, pass it through
        if resp.status_code >= 400:
            return func.HttpResponse(resp.text, status_code=resp.status_code, mimetype="application/json")

        data = resp.json()

        # Add gateway metadata (helps debugging / Copilot reliability)
        result = {
            "meta": {
                "timespan": timespan,
                "max_rows": row_limit,
                "applied_take": True,
                "note": "Results are bounded for reliability (Copilot-safe)."
            },
            "data": data
        }

        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )

    except ValueError as ve:
        return func.HttpResponse(
            json.dumps({"error": str(ve)}),
            status_code=400,
            mimetype="application/json"
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
