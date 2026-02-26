"""Tests for Corsy CORS misconfiguration detection tool."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from tools.vuln.corsy_tool import corsy_scan


def _write_json_to_output_file(data):
    """Return a side_effect for run_command that writes JSON to the -o file."""

    def side_effect(cmd, **_kwargs):
        idx = cmd.index("-o")
        path = Path(cmd[idx + 1])
        path.write_text(json.dumps(data))
        return (0, "", "")

    return side_effect


class TestCorsyScan:
    """Verify Corsy CLI construction and result parsing."""

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        corsy_scan.invoke({"target": "https://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "corsy" in cmd
        assert "-u" in cmd
        assert "-o" in cmd
        assert "--json" not in cmd

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        corsy_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_parses_dict_format(self, _bin, mock_run):
        output = {
            "https://example.com": [
                {
                    "type": "reflect_origin",
                    "description": "Origin is reflected",
                    "severity": "high",
                    "acao_header": "*",
                    "acac_header": "true",
                }
            ]
        }
        mock_run.side_effect = _write_json_to_output_file(output)
        result = corsy_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert result["data"]["findings"][0]["type"] == "reflect_origin"
        assert result["data"]["findings"][0]["severity"] == "high"

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_parses_list_format(self, _bin, mock_run):
        output = [
            {
                "url": "https://example.com",
                "type": "null_origin",
                "description": "Null origin accepted",
                "severity": "medium",
            }
        ]
        mock_run.side_effect = _write_json_to_output_file(output)
        result = corsy_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_no_findings_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = corsy_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0
        assert "no CORS" in result["data"]["message"]

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "connection refused")
        result = corsy_scan.invoke({"target": "https://example.com"})
        assert "connection refused" in result

    @patch("tools.vuln.corsy_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = corsy_scan.invoke({"target": "https://example.com"})
        assert "timeout" in result

    @patch("tools.vuln.corsy_tool.run_command")
    @patch("tools.vuln.corsy_tool.require_binary", return_value=None)
    def test_empty_dict_returns_ok(self, _bin, mock_run):
        mock_run.side_effect = _write_json_to_output_file({})
        result = corsy_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0
