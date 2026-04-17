"""Tests for S3Scanner bucket permission auditing tool."""

from __future__ import annotations

import json
from unittest.mock import patch

from fackel.tools.scanning.s3scanner_tool import s3scanner_scan


class TestS3ScannerScan:
    """Verify S3Scanner CLI construction and result parsing."""

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        s3scanner_scan.invoke({"bucket": "example-backup"})
        cmd = mock_run.call_args[0][0]
        assert "s3scanner" in cmd
        assert "scan" in cmd
        assert "--bucket" in cmd
        assert "example-backup" in cmd
        assert "--provider" in cmd
        assert "aws" in cmd

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_custom_provider(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        s3scanner_scan.invoke({"bucket": "my-bucket", "provider": "gcp"})
        cmd = mock_run.call_args[0][0]
        assert "gcp" in cmd

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_parses_json_results(self, _bin, mock_run):
        scan_result = {
            "bucket": "example-backup",
            "exists": True,
            "public": True,
            "auth_users_read": True,
            "auth_users_write": False,
            "num_objects": 42,
            "region": "us-east-1",
        }
        mock_run.return_value = (0, json.dumps(scan_result) + "\n", "")
        result = s3scanner_scan.invoke({"bucket": "example-backup"})
        assert result["status"] == "ok"
        assert result["data"]["results"][0]["exists"] is True
        assert result["data"]["results"][0]["public"] is True
        assert result["data"]["results"][0]["permissions"]["read"] is True
        assert result["data"]["results"][0]["permissions"]["write"] is False

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_no_results_returns_ok(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        result = s3scanner_scan.invoke({"bucket": "nonexistent-bucket"})
        assert result["status"] == "ok"
        assert result["data"]["results"] == []

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_nonzero_code_no_output_returns_error(self, _bin, mock_run):
        mock_run.return_value = (1, "", "scan failed")
        result = s3scanner_scan.invoke({"bucket": "example-backup"})
        assert result["status"] == "ok"
        assert "scan failed" in result["data"]["message"]

    @patch("fackel.tools.scanning.s3scanner_tool.run_command", side_effect=Exception("timeout"))
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_command_exception_returns_error(self, _bin, _run):
        result = s3scanner_scan.invoke({"bucket": "example-backup"})
        assert "timeout" in result

    def test_rejects_empty_bucket(self):
        result = s3scanner_scan.invoke({"bucket": ""})
        assert "must not be empty" in result

    def test_rejects_invalid_provider(self):
        result = s3scanner_scan.invoke({"bucket": "test", "provider": "alibaba"})
        assert "invalid provider" in result

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_plain_text_fallback(self, _bin, mock_run):
        mock_run.return_value = (0, "bucket exists but not accessible", "")
        result = s3scanner_scan.invoke({"bucket": "example-backup"})
        assert result["status"] == "ok"
        assert "bucket exists but not accessible" in result["data"]["message"]

    @patch("fackel.tools.scanning.s3scanner_tool.run_command")
    @patch("fackel.tools.scanning.s3scanner_tool.require_binary", return_value=None)
    def test_digitalocean_provider(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        s3scanner_scan.invoke({"bucket": "my-spaces", "provider": "digitalocean"})
        cmd = mock_run.call_args[0][0]
        assert "digitalocean" in cmd
