"""Tests for WPScan WordPress vulnerability scanner tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from fackel.tools.vuln.wpscan_tool import _extract_vulns, wpscan_scan


class TestWPScanScan:
    """Verify WPScan CLI construction and result parsing."""

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_basic_command_construction(self, _env, _bin, mock_run):
        mock_run.return_value = (0, "{}", "")
        wpscan_scan.invoke({"target": "https://example.com"})
        cmd = mock_run.call_args[0][0]
        assert "wpscan" in cmd
        assert "--url" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_adds_scheme_when_missing(self, _env, _bin, mock_run):
        mock_run.return_value = (0, "{}", "")
        wpscan_scan.invoke({"target": "example.com"})
        cmd = mock_run.call_args[0][0]
        url_idx = cmd.index("--url") + 1
        assert cmd[url_idx] == "https://example.com"

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_parses_wordpress_version(self, _env, _bin, mock_run):
        data = {
            "version": {
                "number": "6.4",
                "status": "insecure",
                "interesting_entries": ["meta generator"],
                "vulnerabilities": [
                    {"title": "WP Core RCE", "vuln_type": "rce", "fixed_in": "6.4.1"}
                ],
            }
        }
        mock_run.return_value = (0, json.dumps(data), "")
        result = wpscan_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        assert result["data"]["wordpress_version"]["number"] == "6.4"
        assert result["data"]["total_vulnerabilities"] == 1

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_parses_plugins(self, _env, _bin, mock_run):
        data = {
            "plugins": {
                "contact-form-7": {
                    "version": {"number": "5.7"},
                    "outdated": True,
                    "vulnerabilities": [
                        {"title": "CF7 XSS", "vuln_type": "xss", "fixed_in": "5.8"}
                    ],
                }
            }
        }
        mock_run.return_value = (0, json.dumps(data), "")
        result = wpscan_scan.invoke({"target": "https://example.com"})
        assert len(result["data"]["plugins"]) == 1
        assert result["data"]["plugins"][0]["name"] == "contact-form-7"
        assert result["data"]["plugins"][0]["outdated"] is True

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_parses_users(self, _env, _bin, mock_run):
        data = {"users": {"1": {"username": "admin"}, "2": {"username": "editor"}}}
        mock_run.return_value = (0, json.dumps(data), "")
        result = wpscan_scan.invoke({"target": "https://example.com"})
        assert "admin" in result["data"]["users"]
        assert "editor" in result["data"]["users"]

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_empty_output_nonzero_code_returns_error(self, _env, _bin, mock_run):
        mock_run.return_value = (1, "", "scan failed")
        result = wpscan_scan.invoke({"target": "https://example.com"})
        assert "scan failed" in result

    @patch("fackel.tools.vuln.wpscan_tool.run_command", side_effect=Exception("timeout"))
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_command_exception_returns_error(self, _env, _bin, _run):
        result = wpscan_scan.invoke({"target": "https://example.com"})
        assert "timeout" in result

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_malformed_json_returns_error(self, _env, _bin, mock_run):
        mock_run.return_value = (0, "not json", "")
        result = wpscan_scan.invoke({"target": "https://example.com"})
        assert "parse" in result.lower() or "failed" in result.lower()

    def test_extract_vulns_helper(self):
        vulns = [
            {"title": "XSS in widget", "vuln_type": "xss", "fixed_in": "5.8"},
            {"title": "SQLi found", "vuln_type": "sqli", "cvss": {"score": 9.8}},
        ]
        results = _extract_vulns(vulns)
        assert len(results) == 2
        assert results[0]["title"] == "XSS in widget"
        assert results[1]["cvss"] == "9.8"

    @patch("fackel.tools.vuln.wpscan_tool.run_command")
    @patch("fackel.tools.vuln.wpscan_tool.require_binary", return_value=None)
    @patch("fackel.tools.vuln.wpscan_tool.require_env", return_value="token123")
    def test_enumerate_options_passed(self, _env, _bin, mock_run):
        mock_run.return_value = (0, "{}", "")
        wpscan_scan.invoke({"target": "https://example.com", "enumerate": "ap,at,u"})
        cmd = mock_run.call_args[0][0]
        assert "--enumerate" in cmd
        idx = cmd.index("--enumerate") + 1
        assert cmd[idx] == "ap,at,u"
