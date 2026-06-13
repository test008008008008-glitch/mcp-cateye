"""CLI entry point for mcp-cateye."""

from __future__ import annotations

import asyncio
import json
import sys

import click

from . import __version__
from .payloads import Category
from .scanner import fuzz_server, format_findings, format_findings_json


CATEGORY_MAP: dict[str, Category] = {
    "cmd": Category.COMMAND_INJECTION,
    "path": Category.PATH_TRAVERSAL,
    "prompt": Category.PROMPT_INJECTION,
    "ssrf": Category.SSRF,
    "template": Category.TEMPLATE_INJECTION,
    "sql": Category.SQL_INJECTION,
    "xss": Category.XSS,
    "info": Category.INFO_DISCLOSURE,
    "deser": Category.DESERIALIZATION,
}


@click.group()
@click.version_option(version=__version__, prog_name="mcp-cateye")
def main():
    """🐱 mcp-cateye — MCP Server security scanner with fuzzing.

    Cat's eye sees what others miss. Deep inspection of MCP servers
    through active fuzzing, not just static analysis.
    """


@main.command()
@click.argument("command")
@click.argument("args", nargs=-1)
@click.option(
    "--category", "-c",
    multiple=True,
    type=click.Choice(list(CATEGORY_MAP.keys())),
    help="Payload categories to test (default: all)",
)
@click.option(
    "--timeout", "-t",
    default=10.0,
    show_default=True,
    help="Per-request timeout in seconds",
)
@click.option(
    "--concurrency", "-j",
    default=5,
    show_default=True,
    help="Max concurrent fuzz requests",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    help="Output results as JSON",
)
@click.option(
    "--env", "-e",
    multiple=True,
    help="Environment variables in KEY=VALUE format",
)
def fuzz(
    command: str,
    args: tuple[str, ...],
    category: tuple[str, ...],
    timeout: float,
    concurrency: int,
    output_json: bool,
    env: tuple[str, ...],
):
    """Fuzz an MCP server for security vulnerabilities.

    COMMAND is the server executable (e.g., 'python', 'node', 'uvx').

    ARGS are passed to the server command.

    \b
    Examples:
      mcp-cateye fuzz python -m my_mcp_server
      mcp-cateye fuzz uvx mcp-server-git
      mcp-cateye fuzz node server.js -c cmd -c ssrf
      mcp-cateye fuzz python server.py -e API_KEY=test --json
    """
    # Parse categories
    categories: list[Category] | None = None
    if category:
        categories = [CATEGORY_MAP[c] for c in category]

    # Parse env vars
    env_dict: dict[str, str] | None = None
    if env:
        env_dict = {}
        for e in env:
            if "=" not in e:
                raise click.BadParameter(f"Invalid env format: {e} (use KEY=VALUE)")
            key, _, value = e.partition("=")
            env_dict[key] = value

    click.echo(f"🐱 mcp-cateye v{__version__} — scanning...")
    click.echo(f"   Server: {command} {' '.join(args)}")
    if categories:
        click.echo(f"   Categories: {', '.join(c.value for c in categories)}")
    click.echo()

    result = asyncio.run(
        fuzz_server(
            command=command,
            args=list(args),
            env=env_dict,
            categories=categories,
            timeout=timeout,
            concurrency=concurrency,
        )
    )

    if output_json:
        click.echo(format_findings_json(result))
    else:
        click.echo(format_findings(result))

    # Exit with non-zero if critical findings
    if result.critical_count > 0:
        sys.exit(1)


@main.command()
def list_payloads():
    """List all available payload categories and counts."""
    from .payloads import PAYLOADS_BY_CATEGORY

    click.echo("🐱 mcp-cateye — Payload Catalog")
    click.echo()
    for cat, payloads in PAYLOADS_BY_CATEGORY.items():
        click.echo(f"  {cat.value} ({len(payloads)} payloads)")
        for p in payloads:
            click.echo(f"    • {p.description}")
        click.echo()


@main.command()
@click.argument("command")
@click.argument("args", nargs=-1)
@click.option(
    "--env", "-e",
    multiple=True,
    help="Environment variables in KEY=VALUE format",
)
def list_tools(command: str, args: tuple[str, ...], env: tuple[str, ...]):
    """List all tools exposed by an MCP server.

    Useful to see what's available before fuzzing.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env_dict: dict[str, str] | None = None
    if env:
        env_dict = {}
        for e in env:
            key, _, value = e.partition("=")
            env_dict[key] = value

    async def _list():
        server_params = StdioServerParameters(
            command=command,
            args=list(args),
            env=env_dict,
        )
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()

                click.echo(f"🐱 mcp-cateye — Tools on {command} {' '.join(args)}")
                click.echo()
                for tool in tools_result.tools:
                    click.echo(f"  🔧 {tool.name}")
                    if tool.description:
                        click.echo(f"     {tool.description}")
                    if tool.inputSchema:
                        props = tool.inputSchema.get("properties", {})
                        required = tool.inputSchema.get("required", [])
                        for pname, pinfo in props.items():
                            req_mark = " *" if pname in required else ""
                            ptype = pinfo.get("type", "?")
                            pdesc = pinfo.get("description", "")
                            click.echo(f"     └─ {pname}: {ptype}{req_mark}  {pdesc}")
                    click.echo()

    asyncio.run(_list())


if __name__ == "__main__":
    main()
