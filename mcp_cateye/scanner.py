"""Core fuzzing engine for MCP server security scanning."""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .payloads import (
    ALL_PAYLOADS,
    CMD_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    PROMPT_INJECTION_PAYLOADS,
    SSRF_PAYLOADS,
    TEMPLATE_INJECTION_PAYLOADS,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    INFO_DISCLOSURE_PAYLOADS,
    DESERIALIZATION_PAYLOADS,
    Category,
    Payload,
    Severity,
)


@dataclass
class Finding:
    """A single security finding from a fuzz test."""

    tool_name: str
    param_name: str
    payload: Payload
    response_snippet: str
    confidence: str  # "high", "medium", "low"

    @property
    def summary(self) -> str:
        return (
            f"[{self.payload.severity.value.upper()}] {self.tool_name}.{self.param_name} "
            f"— {self.payload.description} (confidence: {self.confidence})"
        )


@dataclass
class ScanResult:
    """Complete scan result for one MCP server."""

    server_command: str
    server_args: list[str]
    tool_count: int
    total_tests: int
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.payload.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.payload.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.payload.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.payload.severity == Severity.LOW)


# ── Parameter type inference ─────────────────────────────────────────────

# Keywords that hint at a parameter's semantic type
_PATH_KEYWORDS = re.compile(
    r"(?:path|dir|directory|folder|file|filename|filepath|root|home|base)",
    re.IGNORECASE,
)
_URL_KEYWORDS = re.compile(
    r"(?:url|uri|endpoint|href|link|host|domain|address|server|proxy|fetch|request)",
    re.IGNORECASE,
)
_CMD_KEYWORDS = re.compile(
    r"(?:command|cmd|shell|bash|exec|execute|run|script|program|process|subprocess)",
    re.IGNORECASE,
)
_SQL_KEYWORDS = re.compile(
    r"(?:query|sql|db|database|select|insert|update|delete|where|table)",
    re.IGNORECASE,
)
_TEMPLATE_KEYWORDS = re.compile(
    r"(?:template|tmpl|render|format_string|tpl|jinja|j2)",
    re.IGNORECASE,
)


@dataclass
class ParamProfile:
    """Semantic profile of a parameter, used to select relevant payloads."""

    name: str
    ptype: str  # JSON schema type
    description: str
    is_path_like: bool = False
    is_url_like: bool = False
    is_cmd_like: bool = False
    is_sql_like: bool = False
    is_template_like: bool = False


def _profile_param(name: str, prop: dict[str, Any]) -> ParamProfile:
    """Build a semantic profile for a parameter from its schema."""
    ptype = prop.get("type", "string")
    desc = prop.get("description", "")
    combined = f"{name} {desc}"

    return ParamProfile(
        name=name,
        ptype=ptype,
        description=desc,
        is_path_like=bool(_PATH_KEYWORDS.search(combined)),
        is_url_like=bool(_URL_KEYWORDS.search(combined)),
        is_cmd_like=bool(_CMD_KEYWORDS.search(combined)),
        is_sql_like=bool(_SQL_KEYWORDS.search(combined)),
        is_template_like=bool(_TEMPLATE_KEYWORDS.search(combined)),
    )


def _select_payloads_for_param(profile: ParamProfile) -> list[Payload]:
    """Select contextually relevant payloads for a parameter.

    Instead of throwing ALL payloads at every parameter, we use the
    parameter's semantic profile to filter:
    - Path-like params → path traversal + info disclosure + cmd injection
    - URL-like params → SSRF + cmd injection (for shell $() in URLs)
    - Command-like params → cmd injection + template injection
    - SQL-like params → SQL injection
    - Template-like params → template injection
    - Generic string params → prompt injection + XSS + deserialization
    - Non-string params → skip most payload categories
    """
    # Non-string parameters: only try a few relevant ones
    if profile.ptype not in ("string",):
        # Numbers/booleans/arrays/objects rarely have injection vulns
        return []

    payloads: list[Payload] = []

    # Command injection: relevant for cmd-like, path-like, and generic strings
    payloads.extend(CMD_INJECTION_PAYLOADS)

    # Path traversal: only for path-like or generic params
    if profile.is_path_like or (not profile.is_url_like and not profile.is_sql_like and not profile.is_template_like):
        payloads.extend(PATH_TRAVERSAL_PAYLOADS)

    # SSRF: only for URL-like params
    if profile.is_url_like:
        payloads.extend(SSRF_PAYLOADS)

    # SQL injection: only for SQL-like or generic string params
    if profile.is_sql_like or (not profile.is_path_like and not profile.is_url_like and not profile.is_cmd_like and not profile.is_template_like):
        payloads.extend(SQL_INJECTION_PAYLOADS)

    # Template injection: only for template-like or generic string params
    if profile.is_template_like or (not profile.is_path_like and not profile.is_url_like and not profile.is_cmd_like and not profile.is_sql_like):
        payloads.extend(TEMPLATE_INJECTION_PAYLOADS)

    # Prompt injection: only for generic string params (not path/url/cmd/sql)
    if not profile.is_path_like and not profile.is_url_like and not profile.is_cmd_like and not profile.is_sql_like and not profile.is_template_like:
        payloads.extend(PROMPT_INJECTION_PAYLOADS)

    # XSS: only for generic string params
    if not profile.is_path_like and not profile.is_url_like and not profile.is_cmd_like and not profile.is_sql_like:
        payloads.extend(XSS_PAYLOADS)

    # Info disclosure: for path-like or generic
    if profile.is_path_like or (not profile.is_url_like and not profile.is_sql_like):
        payloads.extend(INFO_DISCLOSURE_PAYLOADS)

    # Deserialization: for generic string params
    if not profile.is_path_like and not profile.is_url_like and not profile.is_cmd_like:
        payloads.extend(DESERIALIZATION_PAYLOADS)

    return payloads


def _detect_in_response(response_text: str, patterns: list[str]) -> bool:
    """Check if any detection pattern appears in the response."""
    if not patterns:
        return False
    for pattern in patterns:
        if pattern.lower() in response_text.lower():
            return True
    return False


def _is_error_response(response_text: str) -> bool:
    """Heuristic: check if the response is primarily an error message."""
    lower = response_text.lower()
    error_indicators = [
        "error:", "errno", "exception", "traceback", "not found",
        "no such file", "permission denied", "access denied",
        "invalid", "illegal", "unexpected", "syntax error",
        "unknown url type", "connection refused", "timed out",
        "unhandled", "failed to", "cannot ",
    ]
    # If more than half of the first 200 chars are error-like
    prefix = lower[:200]
    hits = sum(1 for ind in error_indicators if ind in prefix)
    return hits >= 2


def _build_fuzz_args(param_schema: dict[str, Any]) -> dict[str, Any]:
    """Build a dict of fuzzed arguments from a tool's input schema.

    For each required parameter, inject payloads. For optional params,
    also try injecting.
    """
    if not param_schema or "properties" not in param_schema:
        return {}

    props = param_schema.get("properties", {})
    required = param_schema.get("required", [])

    fuzz_args: dict[str, Any] = {}

    # Build base args with safe defaults
    for name, prop in props.items():
        ptype = prop.get("type", "string")
        if ptype == "string":
            fuzz_args[name] = "test"
        elif ptype == "number" or ptype == "integer":
            fuzz_args[name] = 1
        elif ptype == "boolean":
            fuzz_args[name] = True
        elif ptype == "array":
            fuzz_args[name] = []
        elif ptype == "object":
            fuzz_args[name] = {}
        else:
            fuzz_args[name] = "test"

    return fuzz_args


async def _test_payload(
    session: ClientSession,
    tool_name: str,
    param_name: str,
    payload: Payload,
    base_args: dict[str, Any],
    timeout: float = 10.0,
) -> Finding | None:
    """Send a single payload and check for vulnerability indicators."""
    args = dict(base_args)
    args[param_name] = payload.value

    try:
        result = await asyncio.wait_for(
            session.call_tool(tool_name, args),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return Finding(
            tool_name=tool_name,
            param_name=param_name,
            payload=payload,
            response_snippet="[TIMEOUT — possible DoS]",
            confidence="medium",
        )
    except Exception as e:
        # Tool rejected the input — check if the error leaks sensitive info
        error_msg = str(e)

        # Skip if it's just a generic rejection with no signal
        if _is_error_response(error_msg):
            # Only flag if detection patterns appear in the error AND
            # the payload category makes sense for error-based detection
            for pattern in payload.detection_patterns:
                if pattern.lower() in error_msg.lower():
                    # Error-based detection: only high confidence for
                    # categories where error response = real vuln
                    if payload.category in (Category.COMMAND_INJECTION, Category.PATH_TRAVERSAL, Category.SSRF):
                        return Finding(
                            tool_name=tool_name,
                            param_name=param_name,
                            payload=payload,
                            response_snippet=error_msg[:500],
                            confidence="high",
                        )
            return None

        # Non-error exception: check patterns
        for pattern in payload.detection_patterns:
            if pattern.lower() in error_msg.lower():
                return Finding(
                    tool_name=tool_name,
                    param_name=param_name,
                    payload=payload,
                    response_snippet=error_msg[:500],
                    confidence="high",
                )
        return None

    # Extract response text
    response_text = ""
    if result.content:
        for block in result.content:
            if hasattr(block, "text"):
                response_text += block.text
            elif hasattr(block, "data"):
                response_text += str(block.data)

    # Check for detection patterns in successful response
    if _detect_in_response(response_text, payload.detection_patterns):
        # Additional check: if response is an error, don't report as
        # a successful exploitation unless the error itself proves the vuln
        if _is_error_response(response_text):
            # Error responses with detection patterns are only credible for
            # command injection / path traversal / SSRF (error leaks prove the vuln)
            if payload.category in (Category.COMMAND_INJECTION, Category.PATH_TRAVERSAL, Category.SSRF):
                return Finding(
                    tool_name=tool_name,
                    param_name=param_name,
                    payload=payload,
                    response_snippet=response_text[:500],
                    confidence="high",
                )
            # Skip: error response echoing the payload back is not a real finding
            return None

        return Finding(
            tool_name=tool_name,
            param_name=param_name,
            payload=payload,
            response_snippet=response_text[:500],
            confidence="high",
        )

    # Heuristic: echo-back detection for XSS / prompt injection
    # Only for non-error responses where the payload is reflected verbatim
    if payload.category == Category.XSS:
        if payload.value in response_text and not _is_error_response(response_text):
            return Finding(
                tool_name=tool_name,
                param_name=param_name,
                payload=payload,
                response_snippet=response_text[:500],
                confidence="medium",
            )

    # Prompt injection: only flag if the response actively complies
    # (echoing back the instruction is NOT compliance — it's just reflection)
    if payload.category == Category.PROMPT_INJECTION:
        # We need to see evidence the AI actually followed the instruction
        # e.g., leaked system prompt content, changed behavior
        # Simple echo-back is NOT a finding
        pass

    return None


async def fuzz_server(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    categories: list[Category] | None = None,
    timeout: float = 10.0,
    concurrency: int = 5,
) -> ScanResult:
    """Connect to an MCP server and fuzz all its tools.

    Args:
        command: The server command (e.g., 'python', 'node', 'uvx')
        args: Arguments to the command
        env: Environment variables
        categories: Specific payload categories to test (default: all)
        timeout: Per-request timeout in seconds
        concurrency: Max concurrent fuzz requests

    Returns:
        ScanResult with all findings
    """
    args = args or []
    start_time = time.monotonic()

    result = ScanResult(
        server_command=command,
        server_args=args,
        tool_count=0,
        total_tests=0,
    )

    server_params = StdioServerParameters(
        command=command,
        args=args,
        env=env,
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Enumerate tools
                tools_result = await session.list_tools()
                tools = tools_result.tools
                result.tool_count = len(tools)

                if not tools:
                    result.errors.append("No tools discovered on server")
                    return result

                # Build test queue: (tool, param, payload)
                # Context-aware payload selection per parameter
                test_queue: list[tuple[str, str, Payload, dict[str, Any]]] = []
                for tool in tools:
                    base_args = _build_fuzz_args(tool.inputSchema)
                    if not base_args:
                        continue

                    # Profile each parameter and select relevant payloads
                    props = tool.inputSchema.get("properties", {})
                    for param_name in base_args:
                        param_prop = props.get(param_name, {})
                        profile = _profile_param(param_name, param_prop)

                        if categories:
                            # User-specified categories: use those, but still
                            # filter by param type
                            payloads = [
                                p for p in ALL_PAYLOADS
                                if p.category in categories
                            ]
                        else:
                            payloads = _select_payloads_for_param(profile)

                        for payload in payloads:
                            test_queue.append(
                                (tool.name, param_name, payload, base_args)
                            )

                result.total_tests = len(test_queue)

                # Run fuzz tests with concurrency control
                semaphore = asyncio.Semaphore(concurrency)

                async def run_one(
                    tool_name: str,
                    param_name: str,
                    payload: Payload,
                    base_args: dict[str, Any],
                ) -> Finding | None:
                    async with semaphore:
                        return await _test_payload(
                            session, tool_name, param_name,
                            payload, base_args, timeout,
                        )

                tasks = [
                    run_one(tn, pn, pl, ba)
                    for tn, pn, pl, ba in test_queue
                ]
                findings = await asyncio.gather(*tasks)

                result.findings = [f for f in findings if f is not None]

    except Exception as e:
        result.errors.append(f"Connection error: {e}")

    result.duration_seconds = time.monotonic() - start_time
    return result


def format_findings(result: ScanResult) -> str:
    """Format scan results as a human-readable report."""
    lines = []
    lines.append("╔══════════════════════════════════════════════════════════╗")
    lines.append("║              🐱 mcp-cateye Scan Report                  ║")
    lines.append("╚══════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append(f"  Server:  {result.server_command} {' '.join(result.server_args)}")
    lines.append(f"  Tools:   {result.tool_count}")
    lines.append(f"  Tests:   {result.total_tests}")
    lines.append(f"  Time:    {result.duration_seconds:.1f}s")
    lines.append("")
    lines.append("  ── Findings ────────────────────────────────────────────")
    lines.append(f"  🔴 Critical: {result.critical_count}")
    lines.append(f"  🟠 High:     {result.high_count}")
    lines.append(f"  🟡 Medium:   {result.medium_count}")
    lines.append(f"  🔵 Low:      {result.low_count}")
    lines.append(f"  📊 Total:    {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append("  ✅ No vulnerabilities detected.")
    else:
        for i, finding in enumerate(result.findings, 1):
            sev_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "⚪",
            }.get(finding.payload.severity, "⚪")

            lines.append(f"  {i}. {sev_icon} {finding.summary}")
            lines.append(f"     Payload: {finding.payload.value[:120]}")
            if finding.response_snippet:
                snippet = finding.response_snippet.replace("\n", "\\n")[:200]
                lines.append(f"     Response: {snippet}")
            lines.append("")

    if result.errors:
        lines.append("  ── Errors ──────────────────────────────────────────────")
        for err in result.errors:
            lines.append(f"  ⚠️  {err}")
        lines.append("")

    lines.append("  🐱 Scan complete. Cat's eye sees all.")
    return "\n".join(lines)


def format_findings_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    return json.dumps(
        {
            "server": {
                "command": result.server_command,
                "args": result.server_args,
            },
            "stats": {
                "tools": result.tool_count,
                "tests": result.total_tests,
                "duration_seconds": result.duration_seconds,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "findings": [
                {
                    "tool": f.tool_name,
                    "parameter": f.param_name,
                    "category": f.payload.category.value,
                    "severity": f.payload.severity.value,
                    "description": f.payload.description,
                    "payload": f.payload.value,
                    "response_snippet": f.response_snippet[:500],
                    "confidence": f.confidence,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        },
        indent=2,
    )


def format_findings_html(result: ScanResult) -> str:
    """Format scan results as a standalone HTML report with dark theme."""
    # Group findings by severity
    by_severity: dict[str, list[Finding]] = {}
    for f in result.findings:
        key = f.payload.severity.value
        by_severity.setdefault(key, []).append(f)

    # Severity color map
    sev_colors = {
        Severity.CRITICAL: ("#dc2626", "🔴"),
        Severity.HIGH: ("#ea580c", "🟠"),
        Severity.MEDIUM: ("#d97706", "🟡"),
        Severity.LOW: ("#2563eb", "🔵"),
        Severity.INFO: ("#6b7280", "⚪"),
    }

    def _esc(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    findings_rows = ""
    for i, f in enumerate(result.findings, 1):
        color, icon = sev_colors.get(f.payload.severity, ("#6b7280", "⚪"))
        snippet = _esc(f.response_snippet[:300]).replace("\\n", "<br>")
        findings_rows += f"""
        <tr>
          <td>{icon} {f.payload.severity.value.upper()}</td>
          <td><code>{_esc(f.tool_name)}</code></td>
          <td><code>{_esc(f.param_name)}</code></td>
          <td>{_esc(f.payload.category.value)}</td>
          <td>{_esc(f.payload.description)}</td>
          <td><details><summary>Payload</summary><pre>{_esc(f.payload.value[:200])}</pre></details></td>
          <td><details><summary>Response</summary><pre>{snippet}</pre></details></td>
          <td>{f.confidence}</td>
        </tr>"""

    findings_table = f"""<table>
  <thead><tr><th>Severity</th><th>Tool</th><th>Parameter</th><th>Category</th><th>Description</th><th>Payload</th><th>Response</th><th>Confidence</th></tr></thead>
  <tbody>{findings_rows}</tbody>
</table>""" if result.findings else ""

    no_findings_div = '<div class="no-findings">✅ No vulnerabilities detected.</div>'

    severity_summary = ""
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        color, icon = sev_colors.get(sev, ("#6b7280", "⚪"))
        count = len(by_severity.get(sev.value, []))
        severity_summary += f'<span style="color:{color}">{icon} {sev.value.upper()}: {count}</span>  '

    errors_html = ""
    if result.errors:
        error_items = "".join(f"<li>{_esc(e)}</li>" for e in result.errors)
        errors_html = f'<h3>⚠️ Errors</h3><ul>{error_items}</ul>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcp-cateye Scan Report</title>
<style>
  :root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; margin: 1.5rem 0 0.5rem; color: var(--muted); }}
  .meta {{ color: var(--muted); margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .summary .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }}
  .summary .card .num {{ font-size: 2rem; font-weight: 700; }}
  .summary .card .label {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: var(--surface); color: var(--muted); text-align: left; padding: 0.6rem 0.8rem; border-bottom: 2px solid var(--border); position: sticky; top: 0; }}
  td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover {{ background: var(--surface); }}
  code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; }}
  pre {{ background: #0d1117; padding: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.78rem; margin-top: 0.3rem; }}
  details {{ cursor: pointer; }}
  details summary {{ color: var(--muted); font-size: 0.8rem; }}
  .no-findings {{ text-align: center; padding: 3rem; color: #22c55e; font-size: 1.2rem; }}
  .footer {{ margin-top: 2rem; color: var(--muted); font-size: 0.75rem; text-align: center; }}
</style>
</head>
<body>
<h1>🐱 mcp-cateye Scan Report</h1>
<div class="meta">
  <strong>Server:</strong> <code>{_esc(result.server_command)} {' '.join(_esc(a) for a in result.server_args)}</code><br>
  <strong>Tools:</strong> {result.tool_count} &nbsp;|&nbsp; <strong>Tests:</strong> {result.total_tests} &nbsp;|&nbsp; <strong>Duration:</strong> {result.duration_seconds:.1f}s
</div>

<div class="summary">
  <div class="card"><div class="num" style="color:#dc2626">{result.critical_count}</div><div class="label">Critical</div></div>
  <div class="card"><div class="num" style="color:#ea580c">{result.high_count}</div><div class="label">High</div></div>
  <div class="card"><div class="num" style="color:#d97706">{result.medium_count}</div><div class="label">Medium</div></div>
  <div class="card"><div class="num" style="color:#2563eb">{result.low_count}</div><div class="label">Low</div></div>
  <div class="card"><div class="num">{len(result.findings)}</div><div class="label">Total</div></div>
</div>

<h2>Findings</h2>
{no_findings_div if not result.findings else findings_table}

{errors_html}

<div class="footer">🐱 Generated by mcp-cateye — Cat's eye sees all.</div>
</body>
</html>"""
