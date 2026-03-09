"""Tests for virustotal_subdomain_enum — VirusTotal passive subdomain enumeration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tools.recon.virustotal_tool import virustotal_subdomain_enum


class TestVirusTotalSubdomainEnum:
    """Verify VirusTotal API integration and subdomain parsing."""

    @patch("tools.recon.virustotal_tool.circuit_breaker")
    @patch("tools.recon.virustotal_tool.get_session")
    @patch("tools.recon.virustotal_tool.require_env", return_value="test-vt-key")
    def test_parses_subdomains(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        api_response = {
            "data": [
                {"id": "sub1.example.com", "type": "domain"},
                {"id": "sub2.example.com", "type": "domain"},
                {"id": "mail.example.com", "type": "domain"},
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = virustotal_subdomain_enum.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["count"] == 3
        assert "sub1.example.com" in result["data"]["subdomains"]
        assert "mail.example.com" in result["data"]["subdomains"]

    @patch("tools.recon.virustotal_tool.circuit_breaker")
    @patch("tools.recon.virustotal_tool.get_session")
    @patch("tools.recon.virustotal_tool.require_env", return_value="test-vt-key")
    def test_empty_results(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": []}
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = virustotal_subdomain_enum.invoke({"domain": "empty.example.com"})

        assert result["status"] == "ok"
        assert result["data"]["count"] == 0
        assert result["data"]["subdomains"] == []

    @patch("tools.recon.virustotal_tool.circuit_breaker")
    @patch("tools.recon.virustotal_tool.get_session")
    @patch("tools.recon.virustotal_tool.require_env", return_value="test-vt-key")
    def test_request_error_raises_tool_exception(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        mock_session.return_value.get.side_effect = requests.RequestException("403 Forbidden")

        result = virustotal_subdomain_enum.invoke({"domain": "example.com"})
        assert "request failed" in result.lower()

    @patch("tools.recon.virustotal_tool.circuit_breaker")
    @patch("tools.recon.virustotal_tool.get_session")
    @patch("tools.recon.virustotal_tool.require_env", return_value="test-vt-key")
    def test_non_json_response(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.side_effect = ValueError("No JSON")
        mock_session.return_value.get.return_value = mock_resp

        result = virustotal_subdomain_enum.invoke({"domain": "example.com"})
        assert "non-json" in result.lower()

    @patch("tools.recon.virustotal_tool.circuit_breaker")
    @patch("tools.recon.virustotal_tool.get_session")
    @patch("tools.recon.virustotal_tool.require_env", return_value="test-vt-key")
    def test_entries_without_id_skipped(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        api_response = {
            "data": [
                {"id": "valid.example.com", "type": "domain"},
                {"type": "domain"},
                {"id": "", "type": "domain"},
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = virustotal_subdomain_enum.invoke({"domain": "example.com"})

        assert result["data"]["count"] == 1
        assert result["data"]["subdomains"] == ["valid.example.com"]
