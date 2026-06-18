"""CLI entry point for mcp-cateye."""

from __future__ import annotations

import asyncio
import json
import sys

import click

from . import __version__
from .payloads import Category
from .scanner import fuzz_server, format_findings, format_findings_json, format_findings_html
from .static_analyzer import (
    run_static_analysis,
    StaticAnalysisResult,
    SecretFinding,
    VulnDep,
    ToolDescFinding,
    ReadinessFinding,
    MCPConfig,
    SecurityScore,
)

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
    """🐱 mcp-cateye — MCP Server security scanner.

    Cat's eye sees what others miss. Combines active fuzzing with
    static analysis for comprehensive MCP security auditing.
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
@click.option(
    "--output", "-o",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    show_default=True,
    help="Output format (--json is shorthand for -o json)",
)
@click.option(
    "--save", "-s",
    type=click.Path(),
    default="",
    help="Save report to a file (e.g., report.html)",
)
def fuzz(
    command: str,
    args: tuple[str, ...],
    category: tuple[str, ...],
    timeout: float,
    concurrency: int,
    output_json: bool,
    env: tuple[str, ...],
    output: str,
    save: str,
):
    """Fuzz an MCP server for security vulnerabilities.

    COMMAND is the server executable (e.g., 'python', 'node', 'uvx').

    ARGS are passed to the server command.

    \b
    Examples:
      mcp-cateye fuzz python -- -m my_mcp_server
      mcp-cateye fuzz uvx -- mcp-server-git
      mcp-cateye fuzz -c cmd -c ssrf node -- server.js
      mcp-cateye fuzz -o html -s report.html python -- server.py
      mcp-cateye fuzz -e API_KEY=test --json python -- server.py
    """
    categories: list[Category] | None = None
    if category:
        categories = [CATEGORY_MAP[c] for c in category]

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

    # --json flag is shorthand for --output json
    if output_json:
        output = "json"

    if output == "json":
        report = format_findings_json(result)
    elif output == "html":
        report = format_findings_html(result)
    else:
        report = format_findings(result)

    if save:
        from pathlib import Path
        Path(save).write_text(report)
        click.echo(f"  📄 Report saved to: {save}")
    else:
        click.echo(report)

    if result.critical_count > 0:
        sys.exit(1)


@main.command()
@click.argument("project_path", required=False, default=".")
@click.option(
    "--clients", "-C",
    multiple=True,
    type=click.Choice(["claude", "cursor", "vscode", "windsurf", "zed", "cline", "roocode", "copilot"]),
    help="MCP clients to scan configs for (default: all)",
)
@click.option(
    "--scan-dirs", "-d",
    multiple=True,
    help="Additional directories to scan for MCP configs",
)
@click.option(
    "--skip-secrets", is_flag=True, help="Skip secrets detection",
)
@click.option(
    "--skip-deps", is_flag=True, help="Skip dependency vulnerability scan",
)
@click.option(
    "--skip-readiness", is_flag=True, help="Skip readiness checks",
)
@click.option(
    "--json", "output_json", is_flag=True, help="Output as JSON",
)
@click.option(
    "--aibom", is_flag=True, help="Generate AI-BOM (CycloneDX format)",
)
def scan(
    project_path: str,
    clients: tuple[str, ...],
    scan_dirs: tuple[str, ...],
    skip_secrets: bool,
    skip_deps: bool,
    skip_readiness: bool,
    output_json: bool,
    aibom: bool,
):
    """Static analysis of MCP server source code and configs.

    \b
    Examples:
      mcp-cateye scan .
      mcp-cateye scan ./my-mcp-server --clients claude --clients cursor
      mcp-cateye scan . --skip-deps --json
      mcp-cateye scan . --aibom
    """
    click.echo(f"🐱 mcp-cateye v{__version__} — static analysis...")
    click.echo(f"   Target: {project_path}")
    click.echo()

    result = run_static_analysis(
        project_path=project_path,
        clients=list(clients) if clients else None,
        scan_dirs=list(scan_dirs) if scan_dirs else None,
        skip_secrets=skip_secrets,
        skip_deps=skip_deps,
        skip_readiness=skip_readiness,
    )

    if output_json:
        click.echo(json.dumps(_serialize_static_result(result), indent=2, default=str))
    else:
        click.echo(_format_static_result(result))

    if aibom and result.aibom:
        bom_path = f"aibom-{project_path.replace('/', '-').strip('.')}.json"
        from pathlib import Path
        Path(bom_path).write_text(json.dumps(result.aibom, indent=2))
        click.echo(f"\n  📋 AI-BOM saved to: {bom_path}")


@main.command()
@click.argument("project_path", required=False, default=".")
@click.option(
    "--clients", "-C",
    multiple=True,
    type=click.Choice(["claude", "cursor", "vscode", "windsurf", "zed", "cline", "roocode", "copilot"]),
    help="MCP clients to scan configs for",
)
@click.option(
    "--json", "output_json", is_flag=True, help="Output as JSON",
)
def score(
    project_path: str,
    clients: tuple[str, ...],
    output_json: bool,
):
    """Quick security score (0-100) and grade (A+ to F).

    \b
    Examples:
      mcp-cateye score .
      mcp-cateye score ./my-mcp-server --json
    """
    result = run_static_analysis(
        project_path=project_path,
        clients=list(clients) if clients else None,
    )

    if not result.score:
        click.echo("No score available.")
        return

    s = result.score
    if output_json:
        click.echo(json.dumps({
            "score": s.overall,
            "grade": s.grade,
            "breakdown": s.breakdown,
            "details": s.details,
        }, indent=2))
    else:
        # Visual score bar
        bar_len = 30
        filled = int(s.overall / 100 * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        # Color the grade
        grade_color = {
            "A+": "🟢", "A": "🟢", "B+": "🟡", "B": "🟡",
            "C": "🟠", "D": "🟠", "F": "🔴",
        }.get(s.grade, "⚪")

        click.echo(f"🐱 mcp-cateye — Security Score")
        click.echo()
        click.echo(f"  {grade_color} {s.grade}  [{bar}]  {s.overall}/100")
        click.echo()
        click.echo("  Breakdown:")
        for cat, sc in s.breakdown.items():
            cat_bar_len = 20
            cat_filled = int(sc / 100 * cat_bar_len)
            cat_bar = "█" * cat_filled + "░" * (cat_bar_len - cat_filled)
            click.echo(f"    {cat:<18} [{cat_bar}] {sc}/100")
        click.echo()
        click.echo(f"  Details: {s.details.get('secrets_critical', 0)} critical secrets, "
                    f"{s.details.get('vulns_critical', 0)} critical vulns, "
                    f"{s.details.get('readiness_issues', 0)} readiness issues")


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
    """List all tools exposed by an MCP server."""
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


# ── Formatters ────────────────────────────────────────────────────────────────


def _format_static_result(result: StaticAnalysisResult) -> str:
    lines = []

    # Configs
    if result.configs:
        lines.append(f"  📁 MCP Configs Found: {len(result.configs)}")
        for cfg in result.configs:
            lines.append(f"     [{cfg.client}] {cfg.server_name} → {cfg.command} {' '.join(cfg.args)}")
        lines.append("")

    # Secrets
    if result.secrets:
        lines.append(f"  🔑 Secrets: {len(result.secrets)} found")
        for s in result.secrets:
            icon = "🔴" if s.severity == "critical" else "🟠" if s.severity == "high" else "🟡"
            lines.append(f"     {icon} [{s.severity.upper()}] {s.secret_type} in {s.file_path}:{s.line}")
            lines.append(f"        {s.snippet}")
        lines.append("")

    # Vulnerable deps
    if result.vuln_deps:
        lines.append(f"  📦 Vulnerable Dependencies: {len(result.vuln_deps)}")
        for v in result.vuln_deps:
            icon = "🔴" if v.severity == "critical" else "🟠" if v.severity == "high" else "🟡"
            lines.append(f"     {icon} [{v.severity.upper()}] {v.package}@{v.version}: {v.vuln_id}")
            lines.append(f"        {v.description[:100]}")
        lines.append("")

    # Tool description issues
    if result.tool_desc_findings:
        lines.append(f"  🛠️  Tool Description Issues: {len(result.tool_desc_findings)}")
        for t in result.tool_desc_findings:
            icon = "🔴" if t.severity == "critical" else "🟠" if t.severity == "high" else "🟡"
            lines.append(f"     {icon} [{t.severity.upper()}] {t.tool_name}: {t.description}")
            lines.append(f"        {t.evidence[:100]}")
        lines.append("")

    # Readiness
    if result.readiness_findings:
        lines.append(f"  🏗️  Readiness Issues: {len(result.readiness_findings)}")
        for r in result.readiness_findings:
            icon = "🔴" if r.severity == "critical" else "🟠" if r.severity == "high" else "🟡"
            lines.append(f"     {icon} [{r.severity.upper()}] {r.file_path}:{r.line}: {r.description}")
        lines.append("")

    # Score
    if result.score:
        s = result.score
        lines.append(f"  🎯 Security Score: {s.grade} ({s.overall}/100)")
        lines.append("")

    if not lines:
        lines.append("  ✅ No issues found.")

    return "\n".join(lines)


def _serialize_static_result(result: StaticAnalysisResult) -> dict:
    data: dict[str, Any] = {
        "configs": [
            {
                "client": c.client,
                "server_name": c.server_name,
                "command": c.command,
                "args": c.args,
                "config_path": c.config_path,
            }
            for c in result.configs
        ],
        "secrets": [
            {
                "file": s.file_path,
                "line": s.line,
                "type": s.secret_type,
                "severity": s.severity,
                "snippet": s.snippet,
            }
            for s in result.secrets
        ],
        "vulnerable_dependencies": [
            {
                "package": v.package,
                "version": v.version,
                "vuln_id": v.vuln_id,
                "severity": v.severity,
                "description": v.description,
            }
            for v in result.vuln_deps
        ],
        "tool_description_issues": [
            {
                "tool": t.tool_name,
                "issue_type": t.issue_type,
                "severity": t.severity,
                "description": t.description,
                "evidence": t.evidence,
            }
            for t in result.tool_desc_findings
        ],
        "readiness_issues": [
            {
                "file": r.file_path,
                "line": r.line,
                "issue": r.issue,
                "severity": r.severity,
                "description": r.description,
            }
            for r in result.readiness_findings
        ],
        "errors": result.errors,
    }
    if result.score:
        data["score"] = {
            "overall": result.score.overall,
            "grade": result.score.grade,
            "breakdown": result.score.breakdown,
            "details": result.score.details,
        }
    if result.aibom:
        data["aibom"] = result.aibom
    return data


if __name__ == "__main__":
    main()
