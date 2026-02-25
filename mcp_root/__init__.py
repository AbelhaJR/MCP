import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    method = body.get("method")
    request_id = body.get("id")

    # tools/list
    if method == "tools/list":
        tools = [
            {
                "name": "query_log_analytics",
                "description": "Run a bounded and safe KQL query against Azure Log Analytics",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "kql": {"type": "string"},
                        "timespan": {"type": "string", "default": "PT1H"},
                        "max_rows": {"type": "integer", "default": 50}
                    },
                    "required": ["kql"]
                }
            }
        ]

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": tools}
        }

    # initialize (VERY IMPORTANT)
    elif method == "initialize":
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "sentinel-mcp",
                    "version": "1.0.0"
                }
            }
        }

    # tools/call
    elif method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "query_log_analytics":
            # call your KQL logic here
            result_text = "Tool executed"

            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {"type": "text", "text": result_text}
                    ]
                }
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": "Tool not found"
                }
            }

    else:
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Method {method} not found"
            }
        }

    return func.HttpResponse(
        json.dumps(response),
        status_code=200,
        mimetype="application/json"
    )
