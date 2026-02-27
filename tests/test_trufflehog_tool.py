"""Tests for TruffleHog secret scanning tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from tools.osint.trufflehog_tool import trufflehog_scan


class TestTrufflehogScan:
    """Verify TruffleHog CLI construction and result parsing."""

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_git_repo_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        trufflehog_scan.invoke({"target": "https://github.com/org/repo"})
        cmd = mock_run.call_args[0][0]
        assert "trufflehog" in cmd
        assert "git" in cmd
        assert "https://github.com/org/repo" in cmd

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_github_org_command(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        trufflehog_scan.invoke({"target": "https://github.com/orgname"})
        cmd = mock_run.call_args[0][0]
        assert "trufflehog" in cmd
        assert "github" in cmd

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_verified_only_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        trufflehog_scan.invoke({"target": "https://github.com/org/repo", "only_verified": True})
        cmd = mock_run.call_args[0][0]
        assert "--only-verified" in cmd

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_no_verified_flag_when_false(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        trufflehog_scan.invoke({"target": "https://github.com/org/repo", "only_verified": False})
        cmd = mock_run.call_args[0][0]
        assert "--only-verified" not in cmd

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_parses_findings(self, _bin, mock_run):
        finding = {
            "DetectorType": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "repository": "https://github.com/org/repo",
                        "file": "config.py",
                        "commit": "abc123",
                    }
                }
            },
        }
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = trufflehog_scan.invoke({"target": "https://github.com/org/repo"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert result["data"]["verified"] == 1
        assert result["data"]["findings"][0]["detector"] == "AWS"
        assert result["data"]["findings"][0]["file"] == "config.py"

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = trufflehog_scan.invoke({"target": "https://github.com/org/repo"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0

    @patch("tools.osint.trufflehog_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = trufflehog_scan.invoke({"target": "https://github.com/org/repo"})
        assert "timeout" in result

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_truncates_raw_value(self, _bin, mock_run):
        finding = {"Raw": "x" * 200, "Verified": False, "SourceMetadata": {}}
        mock_run.return_value = (0, json.dumps(finding) + "\n", "")
        result = trufflehog_scan.invoke({"target": "https://github.com/org/repo"})
        assert len(result["data"]["findings"][0]["raw"]) <= 100

    @patch("tools.osint.trufflehog_tool.run_command")
    @patch("tools.osint.trufflehog_tool.require_binary", return_value=None)
    def test_empty_target_returns_error(self, _bin, mock_run):
        result = trufflehog_scan.invoke({"target": ""})
        assert "empty" in result
