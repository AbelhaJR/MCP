import azure.functions as func
import json

# Import your existing function entrypoint
from QueryKql import main as query_kql_main

def main(req: func.HttpRequest) -> func.HttpResponse:
    body = req.get_json()

    # MCP always passes arguments like this
    arguments = body.get("arguments", {})

    # Create a fake HttpRequest for your existing function
    fake_req = func.HttpRequest(
        method="POST",
        url="/api/QueryKql",
        body=json.dumps(arguments).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        params={}
    )

    return query_kql_main(fake_req)
