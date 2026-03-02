"""Tests for Subzy subdomain takeover detection tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.recon.subzy_tool import subzy_check


class TestSubzyCheck:
    """Verify Subzy CLI construction and result parsing."""

    @patch("tools.recon.subzy_tool.run_command")
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "[]", "")
        subzy_check.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "subzy" in cmd
        assert "run" in cmd
        assert "example.com" in cmd

    @patch("tools.recon.subzy_tool.run_command")
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_parses_vulnerable_finding(self, _bin, mock_run):
        results = [
            {
                "subdomain": "old.example.com",
                "cname": "old.herokuapp.com",
                "service": "heroku",
                "status": "vulnerable",
                "vulnerable": True,
            }
        ]
        mock_run.return_value = (0, json.dumps(results), "")
        result = subzy_check.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["vulnerable"] == 1
        assert result["data"]["findings"][0]["service"] == "heroku"

    @patch("tools.recon.subzy_tool.run_command")
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_parses_non_vulnerable_findings(self, _bin, mock_run):
        results = [
            {
                "subdomain": "www.example.com",
                "cname": "www.example.com.cdn.cloudflare.net",
                "service": "cloudflare",
                "status": "not_vulnerable",
                "vulnerable": False,
            }
        ]
        mock_run.return_value = (0, json.dumps(results), "")
        result = subzy_check.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["vulnerable"] == 0
        assert result["data"]["total"] == 1

    @patch("tools.recon.subzy_tool.run_command")
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = subzy_check.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0
        assert "no takeover" in result["data"]["message"]

    @patch("tools.recon.subzy_tool.run_command")
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "failed to enumerate")
        result = subzy_check.invoke({"target": "example.com"})
        assert "failed to enumerate" in result

    @patch("tools.recon.subzy_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = subzy_check.invoke({"target": "example.com"})
        assert "timeout" in result

    @patch("tools.recon.subzy_tool.run_command")
    @patch("tools.recon.subzy_tool.require_binary", return_value=None)
    def test_malformed_json_returns_ok_empty(self, _bin, mock_run):
        mock_run.return_value = (0, "not json", "")
        result = subzy_check.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0

    def test_rejects_ip_target(self):
        result = subzy_check.invoke({"target": "192.168.1.1"})
        assert "subzy_check" in result

    def test_rejects_url_target(self):
        """URL is accepted after host extraction (guard_target strips scheme/path)."""
        with (
            patch("tools.recon.subzy_tool.require_binary"),
            patch("tools.recon.subzy_tool.run_command") as mock_run,
        ):
            mock_run.return_value = (0, "[]", "")
            result = subzy_check.invoke({"target": "https://example.com/path"})
            assert result["status"] == "ok"
