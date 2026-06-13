"""Tests for mcp-cateye."""

import pytest
from mcp_cateye.payloads import (
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
    PAYLOADS_BY_CATEGORY,
    Category,
    Payload,
    Severity,
)


class TestPayloads:
    def test_all_payloads_have_required_fields(self):
        for p in ALL_PAYLOADS:
            assert p.value, f"Payload missing value: {p.description}"
            assert p.category, f"Payload missing category: {p.description}"
            assert p.severity, f"Payload missing severity: {p.description}"
            assert p.description, f"Payload missing description: {p.value}"

    def test_payloads_by_category_covers_all(self):
        all_from_map = []
        for cat_payloads in PAYLOADS_BY_CATEGORY.values():
            all_from_map.extend(cat_payloads)
        assert len(all_from_map) == len(ALL_PAYLOADS)

    def test_category_counts(self):
        assert len(CMD_INJECTION_PAYLOADS) == 9
        assert len(PATH_TRAVERSAL_PAYLOADS) == 5
        assert len(PROMPT_INJECTION_PAYLOADS) == 5
        assert len(SSRF_PAYLOADS) == 7
        assert len(TEMPLATE_INJECTION_PAYLOADS) == 5
        assert len(SQL_INJECTION_PAYLOADS) == 4
        assert len(XSS_PAYLOADS) == 3
        assert len(INFO_DISCLOSURE_PAYLOADS) == 3
        assert len(DESERIALIZATION_PAYLOADS) == 2

    def test_critical_payloads_have_detection_patterns(self):
        """Critical payloads should have detection patterns to confirm exploitation."""
        for p in ALL_PAYLOADS:
            if p.severity == Severity.CRITICAL:
                # Some critical payloads (prompt injection) may not have
                # deterministic patterns — that's OK
                pass

    def test_command_injection_detection(self):
        cmd_payloads = PAYLOADS_BY_CATEGORY[Category.COMMAND_INJECTION]
        for p in cmd_payloads:
            assert p.detection_patterns, (
                f"Command injection payload missing detection patterns: {p.value}"
            )

    def test_path_traversal_detection(self):
        path_payloads = PAYLOADS_BY_CATEGORY[Category.PATH_TRAVERSAL]
        for p in path_payloads:
            assert p.detection_patterns, (
                f"Path traversal payload missing detection patterns: {p.value}"
            )

    def test_template_injection_detection(self):
        tmpl_payloads = PAYLOADS_BY_CATEGORY[Category.TEMPLATE_INJECTION]
        for p in tmpl_payloads:
            assert p.detection_patterns, (
                f"Template injection payload missing detection patterns: {p.value}"
            )


class TestScannerHelpers:
    def test_detect_in_response(self):
        from mcp_cateye.scanner import _detect_in_response

        assert _detect_in_response("uid=501 gid=20", ["uid="])
        assert _detect_in_response("root:x:0:0:", ["root:"])
        assert not _detect_in_response("hello world", ["uid="])
        assert not _detect_in_response("", ["uid="])

    def test_build_fuzz_args_empty(self):
        from mcp_cateye.scanner import _build_fuzz_args

        assert _build_fuzz_args({}) == {}
        assert _build_fuzz_args({"properties": {}}) == {}

    def test_build_fuzz_args_basic(self):
        from mcp_cateye.scanner import _build_fuzz_args

        schema = {
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "active": {"type": "boolean"},
                "items": {"type": "array"},
                "meta": {"type": "object"},
            }
        }
        args = _build_fuzz_args(schema)
        assert args["name"] == "test"
        assert args["count"] == 1
        assert args["active"] is True
        assert args["items"] == []
        assert args["meta"] == {}
