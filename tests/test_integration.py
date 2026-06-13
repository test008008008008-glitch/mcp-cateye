"""Integration tests — fuzz the vulnerable demo server."""

import sys
import pytest
from mcp_cateye.scanner import fuzz_server, format_findings, format_findings_json
from mcp_cateye.payloads import Category, Severity


@pytest.mark.asyncio
async def test_fuzz_vulnerable_server():
    """Fuzz the deliberately vulnerable demo server and verify findings."""
    result = await fuzz_server(
        command=sys.executable,
        args=["-m", "mcp_cateye.vuln_server"],
        timeout=5.0,
        concurrency=3,
    )

    # Should find tools
    assert result.tool_count > 0, "No tools discovered"
    assert result.total_tests > 0, "No tests run"

    # Should find at least the command injection vulnerability
    cmd_findings = [
        f for f in result.findings
        if f.payload.category == Category.COMMAND_INJECTION
    ]
    assert len(cmd_findings) > 0, (
        "Expected command injection findings but got none. "
        f"Total findings: {len(result.findings)}"
    )

    # Should find path traversal
    path_findings = [
        f for f in result.findings
        if f.payload.category == Category.PATH_TRAVERSAL
    ]
    assert len(path_findings) > 0, "Expected path traversal findings"

    # Should have at least one critical
    assert result.critical_count > 0, "Expected at least one critical finding"


@pytest.mark.asyncio
async def test_fuzz_with_category_filter():
    """Test fuzzing with specific categories only."""
    result = await fuzz_server(
        command=sys.executable,
        args=["-m", "mcp_cateye.vuln_server"],
        categories=[Category.COMMAND_INJECTION],
        timeout=5.0,
        concurrency=3,
    )

    # All findings should be command injection
    for f in result.findings:
        assert f.payload.category == Category.COMMAND_INJECTION, (
            f"Expected only command injection, got {f.payload.category.value}"
        )


def test_format_findings():
    """Test the report formatter."""
    from mcp_cateye.scanner import ScanResult, Finding
    from mcp_cateye.payloads import Payload, Category, Severity

    result = ScanResult(
        server_command="python",
        server_args=["-m", "test"],
        tool_count=2,
        total_tests=100,
        findings=[
            Finding(
                tool_name="run_shell",
                param_name="command",
                payload=Payload(
                    value="$(id)",
                    category=Category.COMMAND_INJECTION,
                    severity=Severity.CRITICAL,
                    description="Subshell command execution",
                    detection_patterns=["uid="],
                ),
                response_snippet="uid=501(cat) gid=20(staff)",
                confidence="high",
            ),
        ],
        duration_seconds=5.0,
    )

    report = format_findings(result)
    assert "CRITICAL" in report
    assert "run_shell" in report
    assert "uid=501" in report
    assert "Cat's eye" in report


def test_format_findings_json():
    """Test JSON output format."""
    from mcp_cateye.scanner import ScanResult, Finding
    from mcp_cateye.payloads import Payload, Category, Severity

    result = ScanResult(
        server_command="python",
        server_args=["-m", "test"],
        tool_count=1,
        total_tests=10,
        findings=[
            Finding(
                tool_name="echo",
                param_name="message",
                payload=Payload(
                    value="<script>alert(1)</script>",
                    category=Category.XSS,
                    severity=Severity.MEDIUM,
                    description="Basic XSS test",
                    detection_patterns=[],
                ),
                response_snippet="<script>alert(1)</script>",
                confidence="low",
            ),
        ],
        duration_seconds=1.0,
    )

    json_str = format_findings_json(result)
    assert '"critical": 0' in json_str
    assert '"medium": 1' in json_str
    assert '"echo"' in json_str
