"""Tests for LinkFinder JavaScript endpoint extraction tool."""

from __future__ import annotations

from unittest.mock import patch

from fackel.tools.recon.linkfinder_tool import linkfinder_extract


class TestLinkFinderExtract:
    """Verify LinkFinder CLI construction and result parsing."""

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        linkfinder_extract.invoke({"target": "https://example.com/app.js"})
        cmd = mock_run.call_args[0][0]
        assert "linkfinder" in cmd
        assert "-i" in cmd
        assert "https://example.com/app.js" in cmd

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        linkfinder_extract.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_parses_endpoints(self, _bin, mock_run):
        out = (
            "/api/v1/users\n"
            "/api/v1/auth/login\n"
            "https://cdn.example.com/assets/main.js\n"
            "/admin/dashboard\n"
        )
        mock_run.return_value = (0, out, "")
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 4
        assert "/api/v1/users" in result["data"]["relative_paths"]
        assert "https://cdn.example.com/assets/main.js" in result["data"]["absolute_urls"]

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_separates_absolute_and_relative(self, _bin, mock_run):
        out = "/api/v1\nhttps://example.com/api\n/admin\n"
        mock_run.return_value = (0, out, "")
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        assert len(result["data"]["relative_paths"]) == 2
        assert len(result["data"]["absolute_urls"]) == 1

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_deduplicates_endpoints(self, _bin, mock_run):
        out = "/api/v1\n/api/v1\n/api/v2\n"
        mock_run.return_value = (0, out, "")
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        assert result["data"]["total"] == 2

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_skips_noise(self, _bin, mock_run):
        out = "/\n//\n/api/real\n"
        mock_run.return_value = (0, out, "")
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        # Should only include /api/real, not / or //
        assert result["data"]["total"] == 1

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0

    @patch("fackel.tools.recon.linkfinder_tool.run_command", side_effect=Exception("timeout"))
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        assert "timeout" in result

    @patch("fackel.tools.recon.linkfinder_tool.run_command")
    @patch("fackel.tools.recon.linkfinder_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "file not found")
        result = linkfinder_extract.invoke({"target": "https://example.com"})
        assert "file not found" in result
