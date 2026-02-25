"""Tests for httpx_scan — HTTP probing and web surface mapping."""

from __future__ import annotations

from unittest.mock import patch

from tools.scanning.httpx_tool import httpx_scan


class TestHttpxCommandConstruction:
    """Verify the subprocess command is built correctly."""

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_target_passed_via_u_flag(self, _bin, mock_run):
        """httpx requires `-u <target>` — not a positional argument."""
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com"})

        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd, "httpx must use -u flag for target"
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "example.com"

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_json_and_silent_flags(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com"})

        cmd = mock_run.call_args[0][0]
        assert "-json" in cmd
        assert "-silent" in cmd

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_tech_detect_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "tech_detect": True})

        cmd = mock_run.call_args[0][0]
        assert "-td" in cmd

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_tech_detect_disabled(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "tech_detect": False})

        cmd = mock_run.call_args[0][0]
        assert "-td" not in cmd

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_follow_redirects_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "follow_redirects": True})

        cmd = mock_run.call_args[0][0]
        assert "-follow-redirects" in cmd

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_status_code_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "status_code": True})

        cmd = mock_run.call_args[0][0]
        assert "-sc" in cmd

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_title_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "title": True})

        cmd = mock_run.call_args[0][0]
        assert "-title" in cmd

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_custom_ports(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "ports": "80,443,8080"})

        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "80,443,8080"

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_empty_ports_omitted(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "ports": ""})

        cmd = mock_run.call_args[0][0]
        assert "-p" not in cmd


class TestHttpxOutputParsing:
    """Verify JSON output is parsed correctly."""

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_valid_jsonl_parsed(self, _bin, mock_run):
        jsonl = (
            '{"url":"https://example.com","status_code":200,"title":"Example"}\n'
            '{"url":"http://example.com","status_code":301}\n'
        )
        mock_run.return_value = (0, jsonl, "")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert len(result["data"]["results"]) == 2
        assert result["data"]["results"][0]["url"] == "https://example.com"

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_no_output_reports_stderr(self, _bin, mock_run):
        """When httpx produces no JSON but exits 0, stderr is forwarded."""
        mock_run.return_value = (0, "", "banner text only")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["error"] == "banner text only"

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_no_output_no_stderr_uses_default_message(self, _bin, mock_run):
        """When httpx produces no JSON and no stderr, a default message is used."""
        mock_run.return_value = (0, "", "")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert "no HTTP services" in (result.get("error") or "")

    @patch("tools.scanning.httpx_tool.run_command")
    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_nonzero_exit_with_no_output_is_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "some error")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert result["status"] == "error"

    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_subprocess_exception(self, _bin):
        with patch(
            "tools.scanning.httpx_tool.run_command",
            side_effect=OSError("command not found"),
        ):
            result = httpx_scan.invoke({"domain": "example.com"})
            assert result["status"] == "error"

    def test_binary_missing(self):
        with patch("tools.scanning.httpx_tool.require_binary") as mock_req:
            mock_req.return_value = {"status": "error", "error": "httpx not found"}
            result = httpx_scan.invoke({"domain": "example.com"})
            assert result["status"] == "error"


class TestHttpxInputValidation:
    """Guard target rejects invalid inputs."""

    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_empty_domain_rejected(self, _bin):
        result = httpx_scan.invoke({"domain": ""})
        assert result["status"] == "error"

    @patch("tools.scanning.httpx_tool.require_binary", return_value=None)
    def test_valid_ip_accepted(self, _bin):
        with patch("tools.scanning.httpx_tool.run_command") as mock_run:
            mock_run.return_value = (0, '{"url":"http://1.2.3.4"}\n', "")
            result = httpx_scan.invoke({"domain": "1.2.3.4"})
            assert result["status"] == "ok"
