"""Tests for Open Redirect scanner tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.vuln.open_redirect_tool import open_redirect_scan


class TestOpenRedirectScan:
    """Verify Open Redirect CLI construction and result parsing."""

    @patch("tools.vuln.open_redirect_tool.run_command")
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        open_redirect_scan.invoke({"target": "https://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "nuclei" in cmd
        assert "-tags" in cmd
        assert "redirect" in cmd[cmd.index("-tags") + 1]

    @patch("tools.vuln.open_redirect_tool.run_command")
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        open_redirect_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.vuln.open_redirect_tool.run_command")
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_findings_parsed(self, _bin, mock_run):
        finding = {
            "template-id": "open-redirect-generic",
            "info": {
                "name": "Open Redirect",
                "severity": "medium",
                "tags": ["redirect"],
                "description": "URL redirection to untrusted site",
            },
            "matched-at": "https://example.com/login?next=http://evil.com",
            "type": "http",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = open_redirect_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1

    @patch("tools.vuln.open_redirect_tool.run_command")
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_host_and_ip_in_findings(self, _bin, mock_run):
        finding = {
            "template-id": "redirect-test",
            "info": {"name": "Redirect", "severity": "medium", "tags": [], "description": ""},
            "matched-at": "https://example.com/login?next=http://evil.com",
            "type": "http",
            "host": "https://example.com",
            "ip": "93.184.216.34",
            "matcher-name": "location-header",
            "extracted-results": ["http://evil.com"],
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = open_redirect_scan.invoke({"target": "https://example.com"})
        f = result["data"]["findings"][0]
        assert f["host"] == "https://example.com"
        assert f["ip"] == "93.184.216.34"
        assert f["matcher_name"] == "location-header"
        assert f["extracted_results"] == ["http://evil.com"]

    @patch("tools.vuln.open_redirect_tool.run_command")
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = open_redirect_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert "no open redirect" in result["data"]["message"]

    @patch(
        "tools.vuln.open_redirect_tool.run_command",
        side_effect=Exception("timeout"),
    )
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = open_redirect_scan.invoke({"target": "https://example.com"})
        assert "timeout" in result

    @patch("tools.vuln.open_redirect_tool.run_command")
    @patch("tools.vuln.open_redirect_tool.require_binary", return_value=None)
    def test_severity_filter(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        open_redirect_scan.invoke({"target": "https://example.com", "severity": "medium,high"})
        cmd = mock_run.call_args[0][0]
        assert "-severity" in cmd
