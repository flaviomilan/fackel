"""Tests for feroxbuster, katana, naabu, and wafw00f scanning tools."""

from __future__ import annotations

from unittest.mock import patch

from tools.scanning.feroxbuster_tool import _find_wordlist, feroxbuster_scan
from tools.scanning.katana_tool import katana_crawl
from tools.scanning.naabu_tool import naabu_scan
from tools.scanning.wafw00f_tool import wafw00f_detect


class TestFeroxbusterScan:
    """Verify feroxbuster CLI construction and result parsing."""

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_preserves_existing_scheme(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "http://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "http://example.com" in cmd
        assert "https://http://example.com" not in cmd

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "no paths found")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["results"] == []

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_jsonl_results_parsed(self, _bin, mock_run, _wl):
        jsonl = (
            '{"type": "response", "url": "https://example.com/admin", '
            '"status": 200, "content_length": 1234}\n'
        )
        mock_run.return_value = (0, jsonl, "")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert len(result["data"]["results"]) == 1
        assert result["data"]["results"][0]["url"] == "https://example.com/admin"

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_nonzero_code_no_results_returns_error(self, _bin, mock_run, _wl):
        mock_run.return_value = (1, "", "scan failed")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert "scan failed" in result

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_wordlist_passed_to_cmd(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "-w" in cmd
        idx = cmd.index("-w")
        assert cmd[idx + 1] == "/mock/wordlist.txt"

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_extensions_passed(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com", "extensions": "php,html"})
        cmd = mock_run.call_args[0][0]
        assert "--extensions" in cmd
        idx = cmd.index("--extensions")
        assert cmd[idx + 1] == "php,html"

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_filter_status_passed(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com", "filter_status": "404,500"})
        cmd = mock_run.call_args[0][0]
        assert cmd.count("--filter-status") == 2

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_depth_and_threads_clamped(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com", "depth": 10, "threads": 100})
        cmd = mock_run.call_args[0][0]
        idx_d = cmd.index("--depth")
        assert cmd[idx_d + 1] == "4"  # clamped to max 4
        idx_t = cmd.index("--threads")
        assert cmd[idx_t + 1] == "50"  # clamped to max 50

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_rate_limit_passed(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com", "rate": 50})
        cmd = mock_run.call_args[0][0]
        assert "--rate-limit" in cmd
        idx = cmd.index("--rate-limit")
        assert cmd[idx + 1] == "50"

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_no_wordlist_raises_error(self, _bin, _wl):
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert "no wordlist found" in result

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_filter_size_passed(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com", "filter_size": "0,1234"})
        cmd = mock_run.call_args[0][0]
        assert cmd.count("--filter-size") == 2

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_filter_words_passed(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com", "filter_words": "42"})
        cmd = mock_run.call_args[0][0]
        assert "--filter-words" in cmd

    @patch(
        "tools.scanning.feroxbuster_tool.run_command",
        side_effect=Exception("connection timeout"),
    )
    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _wl, _run):
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert "connection timeout" in result

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_non_response_entries_filtered(self, _bin, mock_run, _wl):
        jsonl = (
            '{"type": "response", "url": "https://example.com/admin", '
            '"status": 200, "content_length": 1234}\n'
            '{"type": "statistics", "total_requests": 500}\n'
        )
        mock_run.return_value = (0, jsonl, "")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert len(result["data"]["results"]) == 1

    @patch("tools.scanning.feroxbuster_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("tools.scanning.feroxbuster_tool.run_command")
    @patch("tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_multiple_results_parsed(self, _bin, mock_run, _wl):
        jsonl = (
            '{"type": "response", "url": "https://example.com/admin", '
            '"status": 200, "content_length": 1234, "content_type": "text/html", '
            '"words": 100, "lines": 50}\n'
            '{"type": "response", "url": "https://example.com/.env", '
            '"status": 200, "content_length": 56, "content_type": "text/plain", '
            '"words": 10, "lines": 5}\n'
        )
        mock_run.return_value = (0, jsonl, "")
        result = feroxbuster_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 2
        assert result["data"]["results"][0]["url"] == "https://example.com/admin"
        assert result["data"]["results"][1]["url"] == "https://example.com/.env"

    def test_find_wordlist_custom(self):
        assert _find_wordlist("/my/custom.txt") == "/my/custom.txt"

    def test_find_wordlist_bundled_fallback(self):
        result = _find_wordlist("")
        assert isinstance(result, str)
        if result:
            from pathlib import Path

            assert Path(result).is_file()


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
        jsonl = '{"url": "https://example.com/page"}\n{"url": "https://example.com/page"}\n'
        mock_run.return_value = (0, jsonl, "")
        result = katana_crawl.invoke({"target": "example.com"})
        assert len(result["data"]["urls"]) == 1

    @patch("tools.scanning.katana_tool.run_command")
    @patch("tools.scanning.katana_tool.require_binary", return_value=None)
    def test_error_exit_no_results_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "error occurred")
        result = katana_crawl.invoke({"target": "example.com"})
        assert "error occurred" in result


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
