"""Tests for shared tool utilities — format_tool_output, run_command, parse_jsonl."""

import pytest

from fackel.tooling import format_tool_output, parse_jsonl, require_binary


class TestFormatToolOutput:
    """format_tool_output envelope structure."""

    def test_success_envelope(self) -> None:
        result = format_tool_output("my_tool", "example.com", "ok", data={"key": "val"})
        assert result["tool"] == "my_tool"
        assert result["target"] == "example.com"
        assert result["status"] == "ok"
        assert result["data"] == {"key": "val"}
        assert result["error"] is None

    def test_error_envelope(self) -> None:
        result = format_tool_output("my_tool", "example.com", "error", error="broken")
        assert result["status"] == "error"
        assert result["error"] == "broken"
        assert result["data"] is None


class TestParseJsonl:
    """parse_jsonl handles well-formed and malformed input."""

    def test_valid_jsonl(self) -> None:
        output = '{"a":1}\n{"b":2}\n'
        result = parse_jsonl(output)
        assert result == [{"a": 1}, {"b": 2}]

    def test_skips_malformed_lines(self) -> None:
        output = '{"ok":1}\nnot json\n{"also":"ok"}\n'
        result = parse_jsonl(output)
        assert len(result) == 2

    def test_empty_input(self) -> None:
        assert parse_jsonl("") == []

    def test_skips_non_dict_json(self) -> None:
        output = '[1,2,3]\n{"dict":true}\n'
        result = parse_jsonl(output)
        assert result == [{"dict": True}]


class TestRequireBinary:
    """require_binary returns error dict or None."""

    def test_existing_binary(self) -> None:
        # 'python3' should exist in any test environment
        assert require_binary("python3", "test_tool", "target") is None

    def test_missing_binary(self) -> None:
        result = require_binary("nonexistent_binary_xyz_12345", "test_tool", "target")
        assert result is not None
        assert result["status"] == "error"
        assert "not found" in result["error"]
