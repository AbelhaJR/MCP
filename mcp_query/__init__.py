import azure.functions as func
import json
import os

# Import your existing QueryKql function
from QueryKql import main as query_kql_main

EXPECTED_KEY = os.environ.get("MCP_API_KEY")

def main(req: func.HttpRequest) -> func.HttpResponse:
    # API key enforcement
    provided = req.headers.get("x-api-key")
    if not EXPECTED_KEY or provided != EXPECTED_KEY:
        return func.HttpResponse("Unauthorized", status_code=401)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)

    # MCP always sends arguments inside "arguments"
    arguments = body.get("arguments")
    if not isinstance(arguments, dict):
        return func.HttpResponse(
            "Missing 'arguments' object in MCP request",
            status_code=400
        )

    # Build a fake HttpRequest to reuse your existing function
    fake_req = func.HttpRequest(
        method="POST",
        url="/api/QueryKql",
        body=json.dumps(arguments).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        },
        params={}
    )

    # Delegate to your existing function
    return query_kql_main(fake_req)
