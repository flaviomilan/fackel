"""Tests for CloudBrute cloud enumeration tool."""

from __future__ import annotations

from unittest.mock import patch

from fackel.tools.recon.cloudbrute_tool import cloudbrute_enum


class TestCloudBruteEnum:
    """Verify CloudBrute CLI construction and result parsing."""

    @patch("fackel.tools.recon.cloudbrute_tool.run_command")
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        cloudbrute_enum.invoke({"keyword": "acme-corp"})
        cmd = mock_run.call_args[0][0]
        assert "cloudbrute" in cmd
        assert "-d" in cmd
        assert "acme-corp" in cmd

    @patch("fackel.tools.recon.cloudbrute_tool.run_command")
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_cloud_provider_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        cloudbrute_enum.invoke({"keyword": "acme", "cloud": "aws"})
        cmd = mock_run.call_args[0][0]
        assert "-c" in cmd
        assert "aws" in cmd

    @patch("fackel.tools.recon.cloudbrute_tool.run_command")
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_parses_bracket_output(self, _bin, mock_run):
        out = "[aws] acme-backup.s3.amazonaws.com\n[aws] acme-data.s3.amazonaws.com\n"
        mock_run.return_value = (0, out, "")
        result = cloudbrute_enum.invoke({"keyword": "acme"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 2
        assert result["data"]["results"][0]["provider"] == "aws"
        assert "acme-backup" in result["data"]["results"][0]["url"]

    @patch("fackel.tools.recon.cloudbrute_tool.run_command")
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = cloudbrute_enum.invoke({"keyword": "unique-nonexistent"})
        assert result["status"] == "ok"
        assert result["data"]["results"] == []
        assert result["data"]["count"] == 0

    @patch("fackel.tools.recon.cloudbrute_tool.run_command")
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "error occurred")
        result = cloudbrute_enum.invoke({"keyword": "acme"})
        assert "error occurred" in result

    @patch("fackel.tools.recon.cloudbrute_tool.run_command", side_effect=Exception("timeout"))
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = cloudbrute_enum.invoke({"keyword": "acme"})
        assert "timeout" in result

    def test_rejects_empty_keyword(self):
        result = cloudbrute_enum.invoke({"keyword": ""})
        assert "must not be empty" in result

    def test_rejects_invalid_cloud_provider(self):
        result = cloudbrute_enum.invoke({"keyword": "acme", "cloud": "invalid"})
        assert "invalid cloud provider" in result

    @patch("fackel.tools.recon.cloudbrute_tool.run_command")
    @patch("fackel.tools.recon.cloudbrute_tool.require_binary", return_value=None)
    def test_all_providers_no_cloud_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        cloudbrute_enum.invoke({"keyword": "acme", "cloud": ""})
        cmd = mock_run.call_args[0][0]
        assert "-c" not in cmd
