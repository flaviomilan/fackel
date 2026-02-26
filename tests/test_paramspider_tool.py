"""Tests for ParamSpider parameter discovery tool."""

from __future__ import annotations

from unittest.mock import patch

from tools.recon.paramspider_tool import paramspider_crawl


class TestParamSpiderCrawl:
    """Verify ParamSpider CLI construction and result parsing."""

    @patch("tools.recon.paramspider_tool.run_command")
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        paramspider_crawl.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "paramspider" in cmd
        assert "example.com" in cmd

    @patch("tools.recon.paramspider_tool.run_command")
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_parses_urls_with_params(self, _bin, mock_run):
        out = "https://example.com/search?q=FUZZ\nhttps://example.com/page?id=FUZZ&action=FUZZ\n"
        mock_run.return_value = (0, out, "")
        result = paramspider_crawl.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 2
        assert "q" in result["data"]["unique_params"]
        assert "id" in result["data"]["unique_params"]
        assert "action" in result["data"]["unique_params"]

    @patch("tools.recon.paramspider_tool.run_command")
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_deduplicates_urls(self, _bin, mock_run):
        out = (
            "https://example.com/search?q=1\n"
            "https://example.com/search?q=1\n"
            "https://example.com/other?id=2\n"
        )
        mock_run.return_value = (0, out, "")
        result = paramspider_crawl.invoke({"target": "example.com"})
        assert result["data"]["count"] == 2

    @patch("tools.recon.paramspider_tool.run_command")
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = paramspider_crawl.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["urls"] == []
        assert result["data"]["count"] == 0

    @patch("tools.recon.paramspider_tool.run_command")
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_custom_exclude_passed(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        paramspider_crawl.invoke({"target": "example.com", "exclude": "png,jpg"})
        cmd = mock_run.call_args[0][0]
        assert "png,jpg" in cmd

    @patch("tools.recon.paramspider_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = paramspider_crawl.invoke({"target": "example.com"})
        assert "timeout" in result

    @patch("tools.recon.paramspider_tool.run_command")
    @patch("tools.recon.paramspider_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "network error")
        result = paramspider_crawl.invoke({"target": "example.com"})
        assert "network error" in result

    def test_rejects_ip_target(self):
        result = paramspider_crawl.invoke({"target": "192.168.1.1"})
        assert "paramspider_crawl" in result

    def test_rejects_url_target(self):
        """URL is accepted after host extraction (guard_target strips scheme/path)."""
        with (
            patch("tools.recon.paramspider_tool.require_binary"),
            patch("tools.recon.paramspider_tool.run_command") as mock_run,
        ):
            mock_run.return_value = (0, "", "")
            result = paramspider_crawl.invoke({"target": "https://example.com/path"})
            assert result["status"] == "ok"
