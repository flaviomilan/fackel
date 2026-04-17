"""Tests for feroxbuster_scan — recursive directory discovery."""

from __future__ import annotations

import json
from unittest.mock import patch

from fackel.tools.scanning.feroxbuster_tool import feroxbuster_scan


class TestFeroxbusterCommandConstruction:
    """Verify the subprocess command is built correctly."""

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_target_url_passed(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com"})

        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "https://example.com"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_json_and_silent_flags(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com"})

        cmd = mock_run.call_args[0][0]
        assert "--json" in cmd
        assert "--silent" in cmd
        assert "--no-state" in cmd

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_depth_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "depth": 3})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--depth")
        assert cmd[idx + 1] == "3"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_depth_clamped_to_max(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "depth": 99})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--depth")
        assert cmd[idx + 1] == "4"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_threads_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "threads": 30})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--threads")
        assert cmd[idx + 1] == "30"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_threads_clamped_to_max(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "threads": 100})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--threads")
        assert cmd[idx + 1] == "50"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_extensions_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "extensions": "php,html"})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--extensions")
        assert cmd[idx + 1] == "php,html"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_time_limit_present(self, _bin, mock_run):
        """feroxbuster must receive --time-limit so it stops gracefully before the subprocess timeout."""
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com"})

        cmd = mock_run.call_args[0][0]
        assert "--time-limit" in cmd
        idx = cmd.index("--time-limit")
        assert cmd[idx + 1].endswith("s")

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_time_limit_less_than_subprocess_timeout(self, _bin, mock_run):
        """The feroxbuster time-limit must be shorter than the subprocess timeout."""
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com"})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--time-limit")
        ferox_secs = int(cmd[idx + 1].rstrip("s"))
        subprocess_timeout = mock_run.call_args[1].get("timeout", 300)
        assert ferox_secs < subprocess_timeout

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_filter_status_flags(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "filter_status": "404,500"})

        cmd = mock_run.call_args[0][0]
        status_indices = [i for i, v in enumerate(cmd) if v == "--filter-status"]
        assert len(status_indices) == 2
        filtered_codes = {cmd[i + 1] for i in status_indices}
        assert filtered_codes == {"404", "500"}

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_rate_limit_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "https://example.com", "rate": 100})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("--rate-limit")
        assert cmd[idx + 1] == "100"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_scheme_auto_added(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        feroxbuster_scan.invoke({"target": "example.com"})

        cmd = mock_run.call_args[0][0]
        idx = cmd.index("-u")
        assert cmd[idx + 1].startswith("https://")


class TestFeroxbusterOutputParsing:
    """Verify JSON output is parsed correctly."""

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_response_entries_parsed(self, _bin, mock_run):
        entries = [
            {
                "type": "response",
                "url": "https://example.com/admin",
                "status": 200,
                "content_length": 1234,
                "content_type": "text/html",
                "words": 50,
                "lines": 10,
            },
            {
                "type": "response",
                "url": "https://example.com/backup",
                "status": 403,
                "content_length": 500,
                "content_type": "text/html",
                "words": 20,
                "lines": 5,
            },
        ]
        mock_run.return_value = (0, "\n".join(json.dumps(e) for e in entries) + "\n", "")

        result = feroxbuster_scan.invoke({"target": "https://example.com"})

        assert result["status"] == "ok"
        assert result["data"]["total"] == 2
        assert result["data"]["results"][0]["url"] == "https://example.com/admin"

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_non_response_entries_filtered(self, _bin, mock_run):
        """Only 'response' type entries should be included in results."""
        entries = [
            {"type": "statistics", "total_requests": 100},
            {"type": "response", "url": "https://example.com/found", "status": 200},
        ]
        mock_run.return_value = (0, "\n".join(json.dumps(e) for e in entries) + "\n", "")

        result = feroxbuster_scan.invoke({"target": "https://example.com"})

        assert result["data"]["total"] == 1

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_no_results_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "no connections")

        result = feroxbuster_scan.invoke({"target": "https://example.com"})

        assert result["status"] == "ok"
        assert result["data"]["results"] == []

    @patch("fackel.tools.scanning.feroxbuster_tool.run_command")
    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_nonzero_exit_no_output_is_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "fatal error")

        result = feroxbuster_scan.invoke({"target": "https://example.com"})

        assert isinstance(result, str)
        assert "fatal error" in result

    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_subprocess_exception(self, _bin):
        with patch(
            "fackel.tools.scanning.feroxbuster_tool.run_command",
            side_effect=OSError("command not found"),
        ):
            result = feroxbuster_scan.invoke({"target": "https://example.com"})
            assert isinstance(result, str)


class TestFeroxbusterInputValidation:
    """Guard target rejects invalid inputs."""

    @patch("fackel.tools.scanning.feroxbuster_tool.require_binary", return_value=None)
    def test_empty_target_rejected(self, _bin):
        result = feroxbuster_scan.invoke({"target": ""})
        assert isinstance(result, str)
