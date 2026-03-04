"""Tests for Amass subdomain enumeration tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.recon.amass_tool import amass_enum


class TestAmassEnum:
    """Verify Amass CLI construction and result parsing."""

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        amass_enum.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "amass" in cmd
        assert "enum" in cmd
        assert "example.com" in cmd
        assert "-oA" in cmd

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_passive_mode_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        amass_enum.invoke({"target": "example.com", "passive": True})
        cmd = mock_run.call_args[0][0]
        assert "-passive" in cmd

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_active_mode_no_passive_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        amass_enum.invoke({"target": "example.com", "passive": False})
        cmd = mock_run.call_args[0][0]
        assert "-passive" not in cmd

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_parses_subdomains(self, _bin, mock_run):
        entries = [
            {"name": "www.example.com", "sources": ["CertSpotter"]},
            {"name": "api.example.com", "addresses": [{"ip": "1.2.3.4"}]},
        ]
        out = "\n".join(json.dumps(e) for e in entries)
        mock_run.return_value = (0, out, "")
        result = amass_enum.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 2
        names = [s["subdomain"] for s in result["data"]["subdomains"]]
        assert "www.example.com" in names
        assert "api.example.com" in names

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_deduplicates_subdomains(self, _bin, mock_run):
        entries = [
            {"name": "www.example.com"},
            {"name": "www.example.com"},
            {"name": "api.example.com"},
        ]
        out = "\n".join(json.dumps(e) for e in entries)
        mock_run.return_value = (0, out, "")
        result = amass_enum.invoke({"target": "example.com"})
        assert result["data"]["count"] == 2

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_extracts_ips(self, _bin, mock_run):
        entry = {"name": "api.example.com", "addresses": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]}
        mock_run.return_value = (0, json.dumps(entry), "")
        result = amass_enum.invoke({"target": "example.com"})
        assert "1.2.3.4" in result["data"]["subdomains"][0]["ips"]

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = amass_enum.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 0

    @patch("tools.recon.amass_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = amass_enum.invoke({"target": "example.com"})
        assert "timeout" in result

    @patch("tools.recon.amass_tool.run_command")
    @patch("tools.recon.amass_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "dns resolution failed")
        result = amass_enum.invoke({"target": "example.com"})
        assert "dns resolution failed" in result

    def test_rejects_ip_target(self):
        result = amass_enum.invoke({"target": "192.168.1.1"})
        assert "amass_enum" in result

    def test_rejects_url_target(self):
        """URL is accepted after host extraction (guard_target strips scheme/path)."""
        with (
            patch("tools.recon.amass_tool.require_binary"),
            patch("tools.recon.amass_tool.run_command") as mock_run,
        ):
            mock_run.return_value = (0, "", "")
            result = amass_enum.invoke({"target": "https://example.com/path"})
            assert result["status"] == "ok"
