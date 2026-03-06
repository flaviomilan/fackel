"""Tests for nuclei, testssl, and webpage_extractor vulnerability tools."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.vuln.nuclei_tool import nuclei_scan
from tools.vuln.testssl_tool import _parse_severity, testssl_scan
from tools.vuln.webpage_extractor import _extract_text, extract_webpage_content


def _testssl_run(json_content: str = "[]"):
    """Return a side_effect for run_command that writes JSON to the testssl tempfile."""

    def _side_effect(cmd, **_kwargs):
        # The --jsonfile <path> arg pair tells us where to write.
        idx = cmd.index("--jsonfile")
        json_path = Path(cmd[idx + 1])
        json_path.write_text(json_content)
        return 0, "", ""

    return _side_effect


class TestNucleiScan:
    """Verify nuclei CLI construction and result parsing."""

    @patch("tools.vuln.nuclei_tool.run_command")
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        nuclei_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "nuclei" in cmd
        assert "-u" in cmd
        assert "-jsonl" in cmd
        assert "-silent" in cmd

    @patch("tools.vuln.nuclei_tool.run_command")
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_severity_filter_appended(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        nuclei_scan.invoke({"target": "example.com", "severity": "critical,high"})
        cmd = mock_run.call_args[0][0]
        assert "-severity" in cmd

    @patch("tools.vuln.nuclei_tool.run_command")
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_tags_filter_appended(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        nuclei_scan.invoke({"target": "example.com", "tags": "cve,wordpress"})
        cmd = mock_run.call_args[0][0]
        assert "-tags" in cmd

    @patch("tools.vuln.nuclei_tool.run_command")
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_findings_parsed_from_jsonl(self, _bin, mock_run):
        finding = {
            "template-id": "cve-2021-44228",
            "matcher-name": "log4j",
            "info": {"name": "Log4Shell", "severity": "critical", "tags": ["cve"]},
            "matched-at": "https://example.com",
            "type": "http",
            "host": "example.com",
            "ip": "1.2.3.4",
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = nuclei_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert result["data"]["findings"][0]["template_id"] == "cve-2021-44228"

    @patch("tools.vuln.nuclei_tool.run_command")
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_no_findings_returns_message(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = nuclei_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["findings"] == []
        assert "message" in result["data"]

    @patch("tools.vuln.nuclei_tool.run_command")
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_extracted_results_included(self, _bin, mock_run):
        finding = {
            "template-id": "tech-detect",
            "info": {"name": "Tech", "severity": "info"},
            "matched-at": "https://example.com",
            "extracted-results": ["nginx/1.18"],
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = nuclei_scan.invoke({"target": "example.com"})
        assert result["data"]["findings"][0]["extracted_results"] == ["nginx/1.18"]

    @patch("tools.vuln.nuclei_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.vuln.nuclei_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = nuclei_scan.invoke({"target": "example.com"})
        assert "timeout" in result


class TestParseSeverity:
    """Verify severity normalisation."""

    def test_critical(self):
        assert _parse_severity({"severity": "CRITICAL"}) == "critical"

    def test_high(self):
        assert _parse_severity({"severity": "HIGH"}) == "high"

    def test_warn_maps_to_medium(self):
        assert _parse_severity({"severity": "WARN"}) == "medium"

    def test_ok_maps_to_info(self):
        assert _parse_severity({"severity": "OK"}) == "info"

    def test_unknown_maps_to_info(self):
        assert _parse_severity({"severity": "UNKNOWN"}) == "info"

    def test_missing_defaults_to_info(self):
        assert _parse_severity({}) == "info"

    def test_fatal_maps_to_critical(self):
        assert _parse_severity({"severity": "FATAL"}) == "critical"


class TestTestsslScan:
    """Verify testssl.sh CLI and result parsing."""

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_basic_command(self, _bin, mock_run):
        mock_run.side_effect = _testssl_run("[]")
        testssl_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "testssl.sh" in cmd
        assert "--jsonfile" in cmd
        assert "--overwrite" in cmd

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_fast_mode_default(self, _bin, mock_run):
        """Default fast=True adds --fast flag."""
        mock_run.side_effect = _testssl_run("[]")
        testssl_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "--fast" in cmd

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_fast_disabled(self, _bin, mock_run):
        """fast=False omits --fast flag for exhaustive scan."""
        mock_run.side_effect = _testssl_run("[]")
        testssl_scan.invoke({"target": "example.com", "fast": False})
        cmd = mock_run.call_args[0][0]
        assert "--fast" not in cmd

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_openssl_timeout_in_cmd(self, _bin, mock_run):
        """openssl_timeout is passed as --openssl-timeout=N."""
        mock_run.side_effect = _testssl_run("[]")
        testssl_scan.invoke({"target": "example.com", "openssl_timeout": 20})
        cmd = mock_run.call_args[0][0]
        assert "--openssl-timeout=20" in cmd

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_openssl_timeout_clamped(self, _bin, mock_run):
        """openssl_timeout is clamped to 1-30."""
        mock_run.side_effect = _testssl_run("[]")
        testssl_scan.invoke({"target": "example.com", "openssl_timeout": 100})
        cmd = mock_run.call_args[0][0]
        assert "--openssl-timeout=30" in cmd

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_checks_mapped_to_flags(self, _bin, mock_run):
        mock_run.side_effect = _testssl_run("[]")
        testssl_scan.invoke({"target": "example.com", "checks": "protocols,ciphers"})
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert "-E" in cmd

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_findings_parsed(self, _bin, mock_run):
        records = [
            {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
            {"id": "heartbleed", "severity": "HIGH", "finding": "VULNERABLE"},
        ]
        mock_run.side_effect = _testssl_run(json.dumps(records))
        result = testssl_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["summary"]["total"] == 2
        assert result["data"]["summary"]["high"] == 1

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_severity_filter(self, _bin, mock_run):
        records = [
            {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
            {"id": "heartbleed", "severity": "HIGH", "finding": "VULNERABLE"},
        ]
        mock_run.side_effect = _testssl_run(json.dumps(records))
        result = testssl_scan.invoke({"target": "example.com", "severity": "high"})
        assert result["data"]["summary"]["total"] == 1

    @patch("tools.vuln.testssl_tool.run_command")
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_empty_output_returns_ok(self, _bin, mock_run):
        mock_run.side_effect = _testssl_run("")
        result = testssl_scan.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["summary"]["total"] == 0

    @patch("tools.vuln.testssl_tool.run_command", side_effect=Exception("binary not found"))
    @patch("tools.vuln.testssl_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = testssl_scan.invoke({"target": "example.com"})
        assert "binary not found" in result


class TestExtractText:
    """Verify HTML text extraction logic."""

    def test_strips_script_and_style(self):
        html = "<html><script>alert(1)</script><style>.x{}</style><p>Real content here to test</p></html>"
        text = _extract_text(html)
        assert "alert" not in text
        assert "Real content here to test" in text

    def test_strips_nav_footer_header(self):
        html = "<nav>Menu items here</nav><p>Important paragraph content for reading</p><footer>Copyright info</footer>"
        text = _extract_text(html)
        assert "Menu items" not in text
        assert "Important paragraph content" in text

    def test_filters_short_text(self):
        html = "<p>Too short</p><p>This paragraph has sufficient length to pass</p>"
        text = _extract_text(html)
        assert "Too short" not in text
        assert "sufficient length" in text


class TestExtractWebpageContent:
    """Verify the full tool function."""

    @patch("tools.vuln.webpage_extractor.circuit_breaker")
    @patch("tools.vuln.webpage_extractor.get_session")
    def test_successful_extraction(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
        mock_resp.text = "<html><p>This is the main page content for analysis</p></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = extract_webpage_content.invoke({"url": "https://example.com/page"})
        assert result["status"] == "ok"

    @patch("tools.vuln.webpage_extractor.circuit_breaker")
    @patch("tools.vuln.webpage_extractor.get_session")
    def test_non_html_returns_error(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = extract_webpage_content.invoke({"url": "https://example.com/api"})
        assert "not HTML" in result

    @patch("tools.vuln.webpage_extractor.circuit_breaker")
    @patch("tools.vuln.webpage_extractor.get_session")
    def test_truncates_long_content(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        long_text = "A" * 50 + " this is long paragraph content. "
        long_html = "<html>" + "".join(f"<p>{long_text * 10}</p>" for _ in range(50)) + "</html>"
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = long_html
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = extract_webpage_content.invoke({"url": "https://example.com"})
        assert "truncated" in result["data"]["content"]
