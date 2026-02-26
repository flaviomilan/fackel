"""Tests for gau (GetAllUrls) passive URL discovery tool."""

from __future__ import annotations

from unittest.mock import patch

from tools.recon.gau_tool import gau_urls


class TestGauUrls:
    """Verify gau CLI construction and URL parsing."""

    @patch("tools.recon.gau_tool.run_command")
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        gau_urls.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "gau" in cmd
        assert "example.com" in cmd

    @patch("tools.recon.gau_tool.run_command")
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_parses_urls_from_output(self, _bin, mock_run):
        out = "https://example.com/admin\nhttps://example.com/api/v1\nhttps://example.com/login\n"
        mock_run.return_value = (0, out, "")
        result = gau_urls.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 3
        assert "https://example.com/admin" in result["data"]["urls"]
        assert "https://example.com/api/v1" in result["data"]["urls"]

    @patch("tools.recon.gau_tool.run_command")
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_deduplicates_urls(self, _bin, mock_run):
        out = "https://example.com/page\nhttps://example.com/page\nhttps://example.com/other\n"
        mock_run.return_value = (0, out, "")
        result = gau_urls.invoke({"target": "example.com"})
        assert result["data"]["count"] == 2

    @patch("tools.recon.gau_tool.run_command")
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = gau_urls.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["urls"] == []
        assert result["data"]["count"] == 0

    @patch("tools.recon.gau_tool.run_command")
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "fetch failed")
        result = gau_urls.invoke({"target": "example.com"})
        assert "fetch failed" in result

    @patch("tools.recon.gau_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = gau_urls.invoke({"target": "example.com"})
        assert "timeout" in result

    @patch("tools.recon.gau_tool.run_command")
    @patch("tools.recon.gau_tool.require_binary", return_value=None)
    def test_strips_blank_lines(self, _bin, mock_run):
        out = "\nhttps://example.com/a\n\n\nhttps://example.com/b\n\n"
        mock_run.return_value = (0, out, "")
        result = gau_urls.invoke({"target": "example.com"})
        assert result["data"]["count"] == 2

    def test_rejects_ip_target(self):
        result = gau_urls.invoke({"target": "192.168.1.1"})
        assert "gau_urls" in result

    def test_rejects_url_target(self):
        result = gau_urls.invoke({"target": "https://example.com/path"})
        assert "gau_urls" in result
