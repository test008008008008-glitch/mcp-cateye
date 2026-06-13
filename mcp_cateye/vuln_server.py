"""A deliberately vulnerable MCP server for testing mcp-cateye.

DO NOT USE IN PRODUCTION. This server contains intentional vulnerabilities
to demonstrate mcp-cateye's detection capabilities.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


app = Server("vulnerable-demo-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="echo",
            description="Echo back the message. Vulnerable to XSS (echoes input unescaped).",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back",
                    }
                },
                "required": ["message"],
            },
        ),
        Tool(
            name="run_shell",
            description="Run a shell command. INTENTIONALLY VULNERABLE — passes input to shell.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    }
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a file. INTENTIONALLY VULNERABLE — no path sanitization.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to read",
                    }
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="fetch_url",
            description="Fetch a URL. INTENTIONALLY VULNERABLE — allows SSRF.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    }
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="render_template",
            description="Render a template. INTENTIONALLY VULNERABLE — raw eval.",
            inputSchema={
                "type": "object",
                "properties": {
                    "template": {
                        "type": "string",
                        "description": "Template string",
                    },
                    "context": {
                        "type": "string",
                        "description": "JSON context for template rendering",
                    },
                },
                "required": ["template"],
            },
        ),
        Tool(
            name="query_db",
            description="Query the database. INTENTIONALLY VULNERABLE — raw SQL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "SQL query to execute",
                    }
                },
                "required": ["query"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "echo":
        message = arguments.get("message", "")
        return [TextContent(type="text", text=f"You said: {message}")]

    elif name == "run_shell":
        command = arguments.get("command", "")
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=5
            )
            output = result.stdout or result.stderr
            return [TextContent(type="text", text=output)]
        except Exception as e:
            return [TextContent(type="text", text=str(e))]

    elif name == "read_file":
        path = arguments.get("path", "")
        try:
            p = Path(path)
            content = p.read_text()
            return [TextContent(type="text", text=content)]
        except Exception as e:
            return [TextContent(type="text", text=str(e))]

    elif name == "fetch_url":
        import urllib.request
        url = arguments.get("url", "")
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="replace")[:1000]
            return [TextContent(type="text", text=body)]
        except Exception as e:
            return [TextContent(type="text", text=str(e))]

    elif name == "render_template":
        template = arguments.get("template", "")
        context_str = arguments.get("context", "{}")
        try:
            ctx = json.loads(context_str)
            result = template.format(**ctx)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            return [TextContent(type="text", text=str(e))]

    elif name == "query_db":
        query = arguments.get("query", "")
        return [TextContent(type="text", text=f"Executed: {query}")]

    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
