import azure.functions as func
import json
import os

EXPECTED_KEY = os.environ.get("MCP_API_KEY")

def main(req: func.HttpRequest) -> func.HttpResponse:
    # API key enforcement
    provided = req.headers.get("x-api-key")
    if not EXPECTED_KEY or provided != EXPECTED_KEY:
        return func.HttpResponse("Unauthorized", status_code=401)

    tools = {
        "tools": [
            {
                "name": "query_log_analytics",
                "description": "Run a bounded and safe KQL query against Azure Log Analytics",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "kql": {
                            "type": "string",
                            "description": "Kusto Query Language statement"
                        },
                        "timespan": {
                            "type": "string",
                            "description": "ISO 8601 duration (PT15M, PT1H, P1D)",
                            "default": "PT1H"
                        },
                        "max_rows": {
                            "type": "integer",
                            "description": "Maximum number of rows to return",
                            "default": 50
                        }
                    },
                    "required": ["kql"]
                }
            }
        ]
    }

    return func.HttpResponse(
        json.dumps(tools, ensure_ascii=False),
        status_code=200,
        mimetype="application/json"
    )
