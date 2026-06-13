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


def _detect_in_response(response_text: str, patterns: list[str]) -> bool:
    """Check if any detection pattern appears in the response."""
    if not patterns:
        return False
    for pattern in patterns:
        if pattern.lower() in response_text.lower():
            return True
    return False


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
        # Tool rejected the input — could be safe, could be error-based info leak
        error_msg = str(e)
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

    # Check for detection patterns
    if _detect_in_response(response_text, payload.detection_patterns):
        return Finding(
            tool_name=tool_name,
            param_name=param_name,
            payload=payload,
            response_snippet=response_text[:500],
            confidence="high",
        )

    # Heuristic: if the response echoes the payload back unmodified,
    # it might indicate XSS or lack of sanitization
    if payload.category in (Category.XSS, Category.PROMPT_INJECTION):
        if payload.value in response_text:
            return Finding(
                tool_name=tool_name,
                param_name=param_name,
                payload=payload,
                response_snippet=response_text[:500],
                confidence="low",
            )

    # Heuristic: if a command injection payload returned without error
    # but no detection pattern matched, flag as low confidence
    if payload.category == Category.COMMAND_INJECTION:
        if response_text and "error" not in response_text.lower():
            # Couldn't confirm, but worth noting
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

                # Select payloads
                if categories:
                    payloads = [
                        p for p in ALL_PAYLOADS if p.category in categories
                    ]
                else:
                    payloads = list(ALL_PAYLOADS)

                # Build test queue: (tool, param, payload)
                test_queue: list[tuple[str, str, Payload, dict[str, Any]]] = []
                for tool in tools:
                    base_args = _build_fuzz_args(tool.inputSchema)
                    if not base_args:
                        continue
                    for param_name in base_args:
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
