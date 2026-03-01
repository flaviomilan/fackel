"""Tests for shared tool utilities — format_tool_output, run_command, parse_jsonl."""

import pytest
from langchain_core.tools import ToolException

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
    """require_binary raises ToolException when binary is missing."""

    def test_existing_binary(self) -> None:
        require_binary("python3", "test_tool")

    def test_missing_binary(self) -> None:
        with pytest.raises(ToolException, match="not found"):
            require_binary("nonexistent_binary_xyz_12345", "test_tool")
