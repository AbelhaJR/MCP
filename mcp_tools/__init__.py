import azure.functions as func
import json
import os

def main(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({
            "env_key_present": bool(os.environ.get("MCP_API_KEY")),
            "header_present": bool(req.headers.get("x-api-key")),
            "header_value": req.headers.get("x-api-key")
        }),
        mimetype="application/json",
        status_code=200
    )
