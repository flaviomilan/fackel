"""Tests for httpx_scan — HTTP probing and web surface mapping."""

from __future__ import annotations

from unittest.mock import patch

from fackel.tools.scanning.httpx_tool import httpx_scan


class TestHttpxCommandConstruction:
    """Verify the subprocess command is built correctly."""

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_target_passed_via_flag(self, _bin, mock_run):
        """httpx requires `-u <domain>` flag for target."""
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com"})

        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd, "httpx must use -u flag for target"
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "example.com"

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_json_and_silent_flags(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com"})

        cmd = mock_run.call_args[0][0]
        assert "-json" in cmd
        assert "-silent" in cmd

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_tech_detect_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "tech_detect": True})

        cmd = mock_run.call_args[0][0]
        assert "-td" in cmd

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_tech_detect_disabled(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "tech_detect": False})

        cmd = mock_run.call_args[0][0]
        assert "-td" not in cmd

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_follow_redirects_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "follow_redirects": True})

        cmd = mock_run.call_args[0][0]
        assert "-follow-redirects" in cmd

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_status_code_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "status_code": True})

        cmd = mock_run.call_args[0][0]
        assert "-sc" in cmd

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_title_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "title": True})

        cmd = mock_run.call_args[0][0]
        assert "-title" in cmd

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_custom_ports(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "ports": "80,443,8080"})

        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "80,443,8080"

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_empty_ports_omitted(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        httpx_scan.invoke({"domain": "example.com", "ports": ""})

        cmd = mock_run.call_args[0][0]
        assert "-p" not in cmd


class TestHttpxOutputParsing:
    """Verify JSON output is parsed correctly."""

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
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

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_no_output_reports_stderr(self, _bin, mock_run):
        """When httpx produces no JSON but exits 0, stderr is forwarded as data message."""
        mock_run.return_value = (0, "", "banner text only")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["message"] == "banner text only"

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_no_output_no_stderr_uses_default_message(self, _bin, mock_run):
        """When httpx produces no JSON and no stderr, a default message is used."""
        mock_run.return_value = (0, "", "")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert "no HTTP services" in result["data"]["message"]

    @patch("fackel.tools.scanning.httpx_tool.run_command")
    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_nonzero_exit_with_no_output_is_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "some error")

        result = httpx_scan.invoke({"domain": "example.com"})

        assert isinstance(result, str)

    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_subprocess_exception(self, _bin):
        with patch(
            "fackel.tools.scanning.httpx_tool.run_command",
            side_effect=OSError("command not found"),
        ):
            result = httpx_scan.invoke({"domain": "example.com"})
            assert isinstance(result, str)

    def test_binary_missing(self):
        with patch(
            "fackel.tools.scanning.httpx_tool._find_pd_httpx",
            side_effect=__import__(
                "langchain_core.tools", fromlist=["ToolException"]
            ).ToolException("ProjectDiscovery httpx not found in PATH"),
        ):
            result = httpx_scan.invoke({"domain": "example.com"})
            assert isinstance(result, str)
            assert "not found" in result.lower()


class TestHttpxInputValidation:
    """Guard target rejects invalid inputs."""

    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_empty_domain_rejected(self, _bin):
        result = httpx_scan.invoke({"domain": ""})
        assert isinstance(result, str)

    @patch("fackel.tools.scanning.httpx_tool._find_pd_httpx", return_value="/usr/bin/httpx")
    def test_valid_ip_accepted(self, _bin):
        with patch("fackel.tools.scanning.httpx_tool.run_command") as mock_run:
            mock_run.return_value = (0, '{"url":"http://1.2.3.4"}\n', "")
            result = httpx_scan.invoke({"domain": "1.2.3.4"})
            assert result["status"] == "ok"
