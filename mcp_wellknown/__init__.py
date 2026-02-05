import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    manifest = {
        "schema_version": "2024-10-01",
        "name": "mcp-sentinel",
        "description": "MCP server for querying Azure Log Analytics",
        "tools_endpoint": "/mcp/tools"
    }

    return func.HttpResponse(
        json.dumps(manifest),
        status_code=200,
        mimetype="application/json"
    )
