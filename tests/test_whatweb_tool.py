"""Tests for WhatWeb technology fingerprinting tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.recon.whatweb_tool import whatweb_scan


class TestWhatWebScan:
    """Verify WhatWeb CLI construction and result parsing."""

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        whatweb_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "whatweb" in cmd
        assert "--log-json=-" in cmd

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        whatweb_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_parses_technologies(self, _bin, mock_run):
        entry = {
            "target": "https://example.com",
            "plugins": {
                "WordPress": {"version": ["6.4"]},
                "jQuery": {"version": ["3.7.1"]},
                "Apache": {"string": ["2.4.41"]},
                "PHP": {},
            },
        }
        mock_run.return_value = (0, json.dumps(entry) + "\n", "")
        result = whatweb_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 4
        tech_names = [t["name"] for t in result["data"]["technologies"]]
        assert "WordPress" in tech_names
        assert "jQuery" in tech_names

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_extracts_version(self, _bin, mock_run):
        entry = {"plugins": {"WordPress": {"version": ["6.4"]}}}
        mock_run.return_value = (0, json.dumps(entry) + "\n", "")
        result = whatweb_scan.invoke({"target": "example.com"})
        wp = next(t for t in result["data"]["technologies"] if t["name"] == "WordPress")
        assert wp["version"] == "6.4"

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = whatweb_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 0

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_aggression_level_clamped(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        whatweb_scan.invoke({"target": "example.com", "aggression": 5})
        cmd = mock_run.call_args[0][0]
        assert "--aggression=3" in cmd

    @patch("tools.recon.whatweb_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = whatweb_scan.invoke({"target": "example.com"})
        assert "timeout" in result

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "connection refused")
        result = whatweb_scan.invoke({"target": "example.com"})
        assert "connection refused" in result

    @patch("tools.recon.whatweb_tool.run_command")
    @patch("tools.recon.whatweb_tool.require_binary", return_value=None)
    def test_malformed_json_returns_ok_empty(self, _bin, mock_run):
        mock_run.return_value = (0, "not json at all", "")
        result = whatweb_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 0
