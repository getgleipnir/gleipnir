"""A real MCP server built with the official ``mcp`` SDK (v2 MCPServer, or v1 FastMCP)."""

try:
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:  # mcp < 2
    from mcp.server.fastmcp import FastMCP as Server

server = Server("sdk-payments")


@server.tool()
def refund(order: str, amount: int, card: str = "") -> dict:
    """Refund an order."""
    return {"refund_id": f"R-{order}", "amount": amount}


@server.tool()
def explode(reason: str) -> str:
    """Always fails."""
    raise ValueError(f"cannot do that: {reason}")


if __name__ == "__main__":
    server.run()
