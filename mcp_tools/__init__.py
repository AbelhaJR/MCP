import azure.functions as func
import json
import os

EXPECTED_KEY = os.environ.get("MCP_API_KEY")

def main(req: func.HttpRequest) -> func.HttpResponse:
    provided = req.headers.get("x-api-key")
    if not EXPECTED_KEY or provided != EXPECTED_KEY:
        return func.HttpResponse("Unauthorized", status_code=401)

    return func.HttpResponse(
        json.dumps({
            "tools": [
                {
                    "name": "query_log_analytics",
                    "description": "Run a bounded and safe KQL query against Azure Log Analytics",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "kql": { "type": "string" },
                            "timespan": { "type": "string", "default": "PT1H" },
                            "max_rows": { "type": "integer", "default": 50 }
                        },
                        "required": ["kql"]
                    }
                }
            ]
        }),
        status_code=200,
        mimetype="application/json"
    )
