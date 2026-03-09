"""Tests for SQLMap SQL injection scanner tool."""

from __future__ import annotations

from unittest.mock import patch

from tools.vuln.sqlmap_tool import _parse_sqlmap_text, sqlmap_scan


class TestSqlmapScan:
    """Verify SQLMap CLI construction and result parsing."""

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke({"target": "https://example.com/page?id=1"})
        cmd = mock_run.call_args[0][0]
        assert "sqlmap" in cmd
        assert "-u" in cmd
        assert "--batch" in cmd
        assert "https://example.com/page?id=1" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_adds_scheme_when_missing(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "https://example.com" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_level_and_risk_in_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke({"target": "https://example.com/?id=1", "level": 2, "risk": 2})
        cmd = mock_run.call_args[0][0]
        assert "--level=2" in cmd
        assert "--risk=2" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_level_clamped_to_max_3(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke({"target": "https://example.com/?id=1", "level": 5, "risk": 3})
        cmd = mock_run.call_args[0][0]
        assert "--level=3" in cmd
        assert "--risk=2" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_forms_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke({"target": "https://example.com/login", "forms": True})
        cmd = mock_run.call_args[0][0]
        assert "--forms" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_post_data_in_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/login",
                "data": "user=admin&pass=test",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--data" in cmd
        assert "user=admin&pass=test" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_cookie_in_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/?id=1",
                "cookie": "PHPSESSID=abc123",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--cookie" in cmd
        assert "PHPSESSID=abc123" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_technique_filter_in_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/?id=1",
                "technique": "BEU",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--technique" in cmd
        assert "BEU" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_technique_sanitized(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/?id=1",
                "technique": "b;rm -rf",
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--technique" in cmd
        idx = cmd.index("--technique")
        assert cmd[idx + 1] == "B"

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_random_agent_enabled_by_default(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke({"target": "https://example.com/?id=1"})
        cmd = mock_run.call_args[0][0]
        assert "--random-agent" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_random_agent_disabled(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/?id=1",
                "random_agent": False,
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--random-agent" not in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_threads_in_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/?id=1",
                "threads": 3,
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--threads=3" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_threads_clamped_to_5(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        sqlmap_scan.invoke(
            {
                "target": "https://example.com/?id=1",
                "threads": 100,
            }
        )
        cmd = mock_run.call_args[0][0]
        assert "--threads=5" in cmd

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_findings_parsed_from_output(self, _bin, mock_run):
        output = "[INFO] parameter 'id' is vulnerable\n[INFO] boolean-based blind found\n"
        mock_run.return_value = (0, output, "")
        result = sqlmap_scan.invoke({"target": "https://example.com/?id=1"})
        assert result["status"] == "ok"
        assert result["data"]["total"] >= 1

    @patch("tools.vuln.sqlmap_tool.run_command")
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = sqlmap_scan.invoke({"target": "https://example.com/?id=1"})
        assert result["status"] == "ok"
        assert result["data"]["findings"] == []
        assert "message" in result["data"]

    @patch(
        "tools.vuln.sqlmap_tool.run_command",
        side_effect=Exception("timeout"),
    )
    @patch("tools.vuln.sqlmap_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = sqlmap_scan.invoke({"target": "https://example.com/?id=1"})
        assert "timeout" in result


class TestParseSqlmapText:
    """Verify SQLMap text output parsing."""

    def test_detects_vulnerable_parameter(self):
        findings: list = []
        output = "parameter 'username' is vulnerable"
        _parse_sqlmap_text(output, findings)
        assert len(findings) >= 1
        assert any("vulnerable" in f.get("detail", "").lower() for f in findings)

    def test_detects_technique(self):
        findings: list = []
        output = (
            "parameter 'id' appears to be injectable\n"
            "    boolean-based blind\n"
            "    time-based blind\n"
        )
        _parse_sqlmap_text(output, findings)
        techniques = [f["technique"] for f in findings]
        assert "boolean-based blind" in techniques
        assert "time-based blind" in techniques

    def test_empty_output_no_findings(self):
        findings: list = []
        _parse_sqlmap_text("", findings)
        assert len(findings) == 0
