import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    # IMPORTANT: keep discovery anonymous.
    # Copilot Studio may call this without sending API key headers.
    tools_payload = {
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
    }

    return func.HttpResponse(
        json.dumps(tools_payload, ensure_ascii=False),
        status_code=200,
        mimetype="application/json"
    )
