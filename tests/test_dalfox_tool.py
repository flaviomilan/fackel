"""Tests for DalFox XSS scanner tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.vuln.dalfox_tool import _map_severity, dalfox_scan


class TestDalfoxScan:
    """Verify DalFox CLI construction and result parsing."""

    @patch("tools.vuln.dalfox_tool.run_command")
    @patch("tools.vuln.dalfox_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        dalfox_scan.invoke({"target": "https://example.com/search?q=test"})
        cmd = mock_run.call_args[0][0]
        assert "dalfox" in cmd
        assert "url" in cmd
        assert "https://example.com/search?q=test" in cmd

    @patch("tools.vuln.dalfox_tool.run_command")
    @patch("tools.vuln.dalfox_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        dalfox_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.vuln.dalfox_tool.run_command")
    @patch("tools.vuln.dalfox_tool.require_binary", return_value=None)
    def test_findings_parsed_from_jsonl(self, _bin, mock_run):
        finding = {
            "type": "verified",
            "severity": "high",
            "proof_of_concept": "https://example.com/search?q=<script>alert(1)</script>",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "message_str": "XSS found",
            "cwe": "CWE-79",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = dalfox_scan.invoke({"target": "https://example.com/search?q=test"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert result["data"]["findings"][0]["param"] == "q"
        assert result["data"]["findings"][0]["cwe"] == "CWE-79"

    @patch("tools.vuln.dalfox_tool.run_command")
    @patch("tools.vuln.dalfox_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = dalfox_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["findings"] == []
        assert "message" in result["data"]

    @patch("tools.vuln.dalfox_tool.run_command")
    @patch("tools.vuln.dalfox_tool.require_binary", return_value=None)
    def test_multiple_findings(self, _bin, mock_run):
        findings = [
            {"type": "reflected", "param": "q", "payload": "<img src=x>"},
            {"type": "verified", "param": "id", "payload": "<script>alert(1)</script>"},
        ]
        out = "\n".join(json.dumps(f) for f in findings) + "\n"
        mock_run.return_value = (0, out, "")
        result = dalfox_scan.invoke({"target": "https://example.com/search?q=a&id=1"})
        assert result["data"]["total"] == 2

    @patch("tools.vuln.dalfox_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.vuln.dalfox_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = dalfox_scan.invoke({"target": "https://example.com"})
        assert "timeout" in result


class TestMapSeverity:
    """Verify severity normalisation."""

    def test_verified_maps_to_high(self):
        assert _map_severity("verified") == "high"

    def test_reflected_maps_to_medium(self):
        assert _map_severity("reflected") == "medium"

    def test_grep_maps_to_low(self):
        assert _map_severity("grep") == "low"

    def test_unknown_maps_to_info(self):
        assert _map_severity("unknown") == "info"

    def test_high_severity(self):
        assert _map_severity("HIGH") == "high"

    def test_medium_severity(self):
        assert _map_severity("MEDIUM") == "medium"
