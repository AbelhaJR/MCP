import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    request_id = body.get("id")

    tools = [
        {
            "name": "query_log_analytics",
            "description": "Run a bounded and safe KQL query against Azure Log Analytics",
            "inputSchema": {   # ⚠️ camelCase required
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

    response = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "tools": tools
        }
    }

    return func.HttpResponse(
        json.dumps(response),
        status_code=200,
        mimetype="application/json"
    )
