"""Tests for SSRF detection tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.vuln.ssrf_tool import ssrf_detect


class TestSsrfDetect:
    """Verify SSRF detection CLI construction and result parsing."""

    @patch("tools.vuln.ssrf_tool.run_command")
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        ssrf_detect.invoke({"target": "https://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "nuclei" in cmd
        assert "-tags" in cmd
        assert "ssrf" in cmd[cmd.index("-tags") + 1]

    @patch("tools.vuln.ssrf_tool.run_command")
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        ssrf_detect.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.vuln.ssrf_tool.run_command")
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_severity_filter(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        ssrf_detect.invoke({"target": "https://example.com", "severity": "high,critical"})
        cmd = mock_run.call_args[0][0]
        assert "-severity" in cmd

    @patch("tools.vuln.ssrf_tool.run_command")
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_findings_parsed(self, _bin, mock_run):
        finding = {
            "template-id": "ssrf-via-redirect",
            "info": {
                "name": "SSRF via redirect",
                "severity": "high",
                "tags": ["ssrf"],
                "description": "Blind SSRF detected",
            },
            "matched-at": "https://example.com/api?url=http://127.0.0.1",
            "type": "http",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = ssrf_detect.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert result["data"]["findings"][0]["template_id"] == "ssrf-via-redirect"

    @patch("tools.vuln.ssrf_tool.run_command")
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_host_and_ip_in_findings(self, _bin, mock_run):
        finding = {
            "template-id": "ssrf-test",
            "info": {"name": "SSRF", "severity": "high", "tags": [], "description": ""},
            "matched-at": "https://example.com/api",
            "type": "http",
            "host": "https://example.com",
            "ip": "93.184.216.34",
            "matcher-name": "redirect",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = ssrf_detect.invoke({"target": "https://example.com"})
        f = result["data"]["findings"][0]
        assert f["host"] == "https://example.com"
        assert f["ip"] == "93.184.216.34"
        assert f["matcher_name"] == "redirect"

    @patch("tools.vuln.ssrf_tool.run_command")
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = ssrf_detect.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["findings"] == []
        assert "no SSRF" in result["data"]["message"]

    @patch(
        "tools.vuln.ssrf_tool.run_command",
        side_effect=Exception("timeout"),
    )
    @patch("tools.vuln.ssrf_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = ssrf_detect.invoke({"target": "https://example.com"})
        assert "timeout" in result
