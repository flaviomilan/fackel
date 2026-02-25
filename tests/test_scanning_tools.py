"""Tests for feroxbuster, katana, naabu, and wafw00f scanning tools."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from langchain_core.tools import ToolException

from tools.scanning.feroxbuster_tool import feroxbuster_scan
from tools.scanning.katana_tool import katana_crawl
from tools.scanning.naabu_tool import naabu_scan
from tools.scanning.wafw00f_tool import wafw00f_detect


# ── Feroxbuster ────────────────────────────────────────────────────────────


class TestFeroxbusterScan:
    """Verify feroxbuster CLI construction and result parsing."""

    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_preserves_existing_scheme(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "http://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "http://example.com" in cmd
        assert "https://http://example.com" not in cmd

    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "no paths found")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["results"] == []

    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_jsonl_results_parsed(self, _bin, mock_run):
        jsonl = '{"url": "https://example.com/admin", "status": 200, "content_length": 1234}\n'
        mock_run.return_value = (0, jsonl, "")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert len(result["data"]["results"]) == 1
        assert result["data"]["results"][0]["url"] == "https://example.com/admin"

    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "scan failed")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert "scan failed" in result


# ── Katana crawl ───────────────────────────────────────────────────────────


class TestKatanaCrawl:
    """Verify katana CLI construction and URL extraction."""

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        katana_crawl.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_url_extraction_new_format(self, _bin, mock_run):
        jsonl = '{"request": {"endpoint": "https://example.com/api"}}\n'
        mock_run.return_value = (0, jsonl, "")
        result = katana_crawl.invoke({"target": "example.com"})
        assert "https://example.com/api" in result["data"]["urls"]

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_url_extraction_old_format(self, _bin, mock_run):
        jsonl = '{"url": "https://example.com/page"}\n'
        mock_run.return_value = (0, jsonl, "")
        result = katana_crawl.invoke({"target": "example.com"})
        assert "https://example.com/page" in result["data"]["urls"]

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = katana_crawl.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["urls"] == []

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_deduplicates_urls(self, _bin, mock_run):
        jsonl = (
            '{"url": "https://example.com/page"}\n'
            '{"url": "https://example.com/page"}\n'
        )
        mock_run.return_value = (0, jsonl, "")
        result = katana_crawl.invoke({"target": "example.com"})
        assert len(result["data"]["urls"]) == 1

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_error_exit_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "error occurred")
        result = katana_crawl.invoke({"target": "example.com"})
        assert "error occurred" in result


# ── Naabu ──────────────────────────────────────────────────────────────────


class TestNaabuScan:
    """Verify naabu CLI construction and port parsing."""

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_host_passed_correctly(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        naabu_scan.invoke({"host": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "-host" in cmd
        idx = cmd.index("-host")
        assert cmd[idx + 1] == "example.com"

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_ports_passed(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        naabu_scan.invoke({"host": "example.com", "ports": "80,443"})
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "80,443"

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_top_ports_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        naabu_scan.invoke({"host": "example.com", "top_ports": "100"})
        cmd = mock_run.call_args[0][0]
        assert "-top-ports" in cmd

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_rate_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        naabu_scan.invoke({"host": "example.com", "rate": 5000})
        cmd = mock_run.call_args[0][0]
        assert "-rate" in cmd
        idx = cmd.index("-rate")
        assert cmd[idx + 1] == "5000"

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_skip_cdn_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        naabu_scan.invoke({"host": "example.com", "skip_cdn": True})
        cmd = mock_run.call_args[0][0]
        assert "-cdn" in cmd

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_jsonl_results_parsed(self, _bin, mock_run):
        jsonl = '{"host": "example.com", "port": 80}\n{"host": "example.com", "port": 443}\n'
        mock_run.return_value = (0, jsonl, "")
        result = naabu_scan.invoke({"host": "example.com"})
        assert result["status"] == "ok"
        assert len(result["data"]["results"]) == 2

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = naabu_scan.invoke({"host": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["results"] == []

    @patch("tools.scanning.naabu_tool.run_command")
    @patch("tools.scanning.naabu_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "scan failed")
        result = naabu_scan.invoke({"host": "example.com"})
        assert "scan failed" in result


# ── Wafw00f ────────────────────────────────────────────────────────────────


class TestWafw00fDetect:
    """Verify wafw00f CLI construction and result parsing."""

    @patch("tools.scanning.wafw00f_tool.run_command")
    @patch("tools.scanning.wafw00f_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, '{"identified": []}', "")
        wafw00f_detect.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.scanning.wafw00f_tool.run_command")
    @patch("tools.scanning.wafw00f_tool.require_binary", return_value=None)
    def test_check_all_flag(self, _bin, mock_run):
        mock_run.return_value = (0, '{"identified": []}', "")
        wafw00f_detect.invoke({"target": "example.com", "check_all": True})
        cmd = mock_run.call_args[0][0]
        assert "-a" in cmd

    @patch("tools.scanning.wafw00f_tool.run_command")
    @patch("tools.scanning.wafw00f_tool.require_binary", return_value=None)
    def test_json_result_parsed(self, _bin, mock_run):
        payload = '{"identified": ["Cloudflare"], "waf_name": "Cloudflare", "manufacturer": "Cloudflare Inc."}'
        mock_run.return_value = (0, payload, "")
        result = wafw00f_detect.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["waf_name"] == "Cloudflare"

    @patch("tools.scanning.wafw00f_tool.run_command")
    @patch("tools.scanning.wafw00f_tool.require_binary", return_value=None)
    def test_invalid_json_no_error_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "not json", "")
        result = wafw00f_detect.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["identified"] == []

    @patch("tools.scanning.wafw00f_tool.run_command")
    @patch("tools.scanning.wafw00f_tool.require_binary", return_value=None)
    def test_error_code_no_data_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "scan failed")
        result = wafw00f_detect.invoke({"target": "example.com"})
        assert "scan failed" in result
