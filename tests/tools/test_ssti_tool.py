"""Tests for SSTI detection tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from fackel.tools.vuln.ssti_tool import ssti_scan


class TestSstiScan:
    """Verify SSTI detection CLI construction and result parsing."""

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        ssti_scan.invoke({"target": "https://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "nuclei" in cmd
        assert "-tags" in cmd
        assert "ssti" in cmd[cmd.index("-tags") + 1]

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        ssti_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_findings_parsed(self, _bin, mock_run):
        finding = {
            "template-id": "ssti-jinja2",
            "info": {
                "name": "Jinja2 SSTI",
                "severity": "critical",
                "tags": ["ssti"],
                "description": "Server-Side Template Injection in Jinja2",
            },
            "matched-at": "https://example.com/render?name={{7*7}}",
            "type": "http",
            "extracted-results": ["49"],
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = ssti_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert result["data"]["findings"][0]["extracted_results"] == ["49"]

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_host_and_ip_in_findings(self, _bin, mock_run):
        finding = {
            "template-id": "ssti-test",
            "info": {"name": "SSTI", "severity": "high", "tags": [], "description": ""},
            "matched-at": "https://example.com/render",
            "type": "http",
            "host": "https://example.com",
            "ip": "93.184.216.34",
            "matcher-name": "eval-result",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = ssti_scan.invoke({"target": "https://example.com"})
        f = result["data"]["findings"][0]
        assert f["host"] == "https://example.com"
        assert f["ip"] == "93.184.216.34"
        assert f["matcher_name"] == "eval-result"

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = ssti_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert "no SSTI" in result["data"]["message"]

    @patch(
        "fackel.tools.vuln.ssti_tool.run_command",
        side_effect=Exception("timeout"),
    )
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = ssti_scan.invoke({"target": "https://example.com"})
        assert "timeout" in result

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_severity_filter(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        ssti_scan.invoke({"target": "https://example.com", "severity": "critical"})
        cmd = mock_run.call_args[0][0]
        assert "-severity" in cmd

    @patch("fackel.tools.vuln.ssti_tool.run_command")
    @patch("fackel.tools.vuln.ssti_tool.require_binary", return_value=None)
    def test_curl_command_preserved(self, _bin, mock_run):
        finding = {
            "template-id": "ssti-generic",
            "info": {"name": "SSTI", "severity": "high", "tags": [], "description": ""},
            "matched-at": "https://example.com/render",
            "type": "http",
            "curl-command": "curl -X POST https://example.com/render -d 'name={{7*7}}'",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = ssti_scan.invoke({"target": "https://example.com"})
        assert "curl_command" in result["data"]["findings"][0]
