from fastmcp import FastMCP

mcp = FastMCP("SentinelMCP")

@mcp.tool
def ping() -> dict:
    return {"ok": True, "message": "pong"}

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
