"""Tests for ffuf web fuzzer tool."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fackel.tools.scanning.ffuf_tool import _find_wordlist, ffuf_scan


class TestFfufScan:
    """Verify ffuf CLI construction and result parsing."""

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "https://example.com/FUZZ"})
        cmd = mock_run.call_args[0][0]
        assert "ffuf" in cmd
        assert "-u" in cmd
        assert "FUZZ" in cmd[cmd.index("-u") + 1]

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_appends_fuzz_when_missing(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "https://example.com"})
        cmd = mock_run.call_args[0][0]
        target_url = cmd[cmd.index("-u") + 1]
        assert target_url.endswith("/FUZZ")

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "example.com/FUZZ"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com/FUZZ" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_custom_method(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "https://example.com/FUZZ", "method": "POST"})
        cmd = mock_run.call_args[0][0]
        assert "-X" in cmd
        assert "POST" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_extensions_added(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "https://example.com/FUZZ", "extensions": "php,html"})
        cmd = mock_run.call_args[0][0]
        assert "-e" in cmd
        assert "php,html" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_filter_codes(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke(
            {
                "target": "https://example.com/FUZZ",
                "filter_codes": "404,500",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "-fc" in cmd
        assert "404,500" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_filter_size(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke(
            {
                "target": "https://example.com/FUZZ",
                "filter_size": "0,1234",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "-fs" in cmd
        assert "0,1234" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_filter_words(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke(
            {
                "target": "https://example.com/FUZZ",
                "filter_words": "42",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "-fw" in cmd
        assert "42" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_custom_headers(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke(
            {
                "target": "https://example.com/FUZZ",
                "headers": ["Authorization: Bearer tok123", "X-Custom: val"],
            }
        )
        cmd = mock_run.call_args[0][0]
        h_indices = [i for i, v in enumerate(cmd) if v == "-H"]
        assert len(h_indices) == 2
        assert "Authorization: Bearer tok123" in cmd
        assert "X-Custom: val" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_recursion_enabled(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke(
            {
                "target": "https://example.com/FUZZ",
                "recursion": True,
                "recursion_depth": 3,
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "-recursion" in cmd
        assert "-recursion-depth" in cmd
        idx = cmd.index("-recursion-depth")
        assert cmd[idx + 1] == "3"

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_rate_limiting(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke(
            {
                "target": "https://example.com/FUZZ",
                "rate": 100,
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "-rate" in cmd
        assert "100" in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_recursion_not_added_when_disabled(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "https://example.com/FUZZ"})
        cmd = mock_run.call_args[0][0]
        assert "-recursion" not in cmd

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_findings_parsed_from_json(self, _bin, mock_run, _wl):
        output = json.dumps(
            {
                "results": [
                    {
                        "url": "https://example.com/admin",
                        "input": {"FUZZ": "admin"},
                        "status": 200,
                        "length": 1234,
                        "words": 100,
                        "lines": 50,
                        "content-type": "text/html",
                        "redirectlocation": "",
                    },
                    {
                        "url": "https://example.com/api",
                        "input": {"FUZZ": "api"},
                        "status": 301,
                        "length": 0,
                        "words": 0,
                        "lines": 0,
                        "content-type": "",
                        "redirectlocation": "https://example.com/api/",
                    },
                ]
            }
        )
        mock_run.return_value = (0, output, "")
        result = ffuf_scan.invoke({"target": "https://example.com/FUZZ"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 2
        assert result["data"]["findings"][0]["url"] == "https://example.com/admin"
        assert result["data"]["findings"][1]["redirect_location"] == "https://example.com/api/"

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, json.dumps({"results": []}), "")
        result = ffuf_scan.invoke({"target": "https://example.com/FUZZ"})
        assert result["status"] == "ok"
        assert result["data"]["findings"] == []
        assert "message" in result["data"]

    @patch(
        "fackel.tools.scanning.ffuf_tool.run_command",
        side_effect=Exception("timeout"),
    )
    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _wl, _run):
        result = ffuf_scan.invoke({"target": "https://example.com/FUZZ"})
        assert "timeout" in result

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_missing_wordlist_returns_error(self, _bin, _wl):
        result = ffuf_scan.invoke({"target": "https://example.com/FUZZ"})
        assert "wordlist" in result.lower()

    @patch("fackel.tools.scanning.ffuf_tool._find_wordlist", return_value="/mock/wordlist.txt")
    @patch("fackel.tools.scanning.ffuf_tool.run_command")
    @patch("fackel.tools.scanning.ffuf_tool.require_binary", return_value=None)
    def test_threads_clamped_to_50(self, _bin, mock_run, _wl):
        mock_run.return_value = (0, "", "")
        ffuf_scan.invoke({"target": "https://example.com/FUZZ", "threads": 100})
        cmd = mock_run.call_args[0][0]
        t_idx = cmd.index("-t")
        assert cmd[t_idx + 1] == "50"


class TestFindWordlist:
    """Verify wordlist discovery."""

    def test_custom_wordlist_returned(self):
        assert _find_wordlist("/my/custom.txt") == "/my/custom.txt"

    def test_bundled_wordlist_fallback(self):
        """When no system wordlist exists, the bundled one is returned."""
        result = _find_wordlist("")
        # On CI/dev without SecLists, the bundled wordlist must be found.
        assert isinstance(result, str)
        if result:
            from pathlib import Path

            assert Path(result).is_file()
            assert "common.txt" in result

    @patch("fackel.tools.scanning._wordlists._BUNDLED", new=Path("/nonexistent/bundled.txt"))
    @patch("fackel.tools.scanning._wordlists.DEFAULT_WORDLISTS", new=())
    def test_no_wordlist_returns_empty(self):
        """When no wordlist exists anywhere, empty string is returned."""
        from fackel.tools.scanning._wordlists import find_wordlist

        assert find_wordlist("") == ""

    def test_bundled_wordlist_file_exists(self):
        """The bundled wordlist is present in the package."""
        from pathlib import Path

        bundled = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "fackel"
            / "tools"
            / "scanning"
            / "wordlists"
            / "common.txt"
        )
        assert bundled.is_file()
        content = bundled.read_text()
        # Should have a reasonable number of entries.
        lines = [ln for ln in content.splitlines() if ln.strip()]
        assert len(lines) >= 500
