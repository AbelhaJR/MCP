from __future__ import annotations

from fastmcp import FastMCP

from .catalog import WorkspaceCatalog
from .config import get_settings, validate_required_settings
from .responses import ok
from .tools.analytics import register_analytics_tools
from .tools.catalog import register_catalog_tools
from .tools.investigation import register_investigation_tools
from .tools.query import register_query_tools


settings = get_settings()
catalog = WorkspaceCatalog(settings.catalog_path)

mcp = FastMCP("SentinelMCPEnterprise")


_TOOL_DEFS: list[dict] = []


@mcp.tool
def ping() -> dict:
    """Simple MCP health check."""
    return ok({
        "message": "pong",
        "workspace_configured": bool(settings.workspace_id),
        "catalog_loaded": bool(catalog.data),
        "missing_settings": validate_required_settings(settings),
        "mcp_path": "/mcp",
    })


_TOOL_DEFS.append({
    "name": "ping",
    "description": "Connectivity and configuration health check.",
    "params": {},
})


_TOOL_DEFS.extend(register_catalog_tools(mcp, settings, catalog))
_TOOL_DEFS.extend(register_investigation_tools(mcp, settings, catalog))
_TOOL_DEFS.extend(register_analytics_tools(mcp, settings))
_TOOL_DEFS.extend(register_query_tools(mcp, settings))


@mcp.tool
def get_tools() -> dict:
    """Returns the exact MCP tool list and parameter formats."""
    return ok({"tools": _TOOL_DEFS, "mcp_path": "/mcp"})


_TOOL_DEFS.insert(0, {
    "name": "get_tools",
    "description": "Returns the exact MCP tool list and parameter formats.",
    "params": {},
})


asgi_app = mcp.http_app(path="/mcp", stateless_http=True)