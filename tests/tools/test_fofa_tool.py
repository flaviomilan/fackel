"""Tests for FOFA asset search tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fackel.tools.recon.fofa_tool import fofa_search


class TestFofaSearch:
    """Verify FOFA API integration and result parsing."""

    @patch("fackel.tools.recon.fofa_tool.circuit_breaker")
    @patch("fackel.tools.recon.fofa_tool.get_session")
    @patch("fackel.tools.recon.fofa_tool.require_env", side_effect=["user@example.com", "fake-key"])
    def test_parses_results(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        api_response = {
            "error": False,
            "size": 2,
            "results": [
                [
                    "https://example.com",
                    "1.2.3.4",
                    "443",
                    "https",
                    "nginx",
                    "Example",
                    "example.com",
                    "ExampleOrg",
                    "HTTP/1.1 200",
                ],
                [
                    "http://sub.example.com",
                    "5.6.7.8",
                    "80",
                    "http",
                    "apache",
                    "Sub",
                    "example.com",
                    "ExampleOrg",
                    "HTTP/1.1 301",
                ],
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = fofa_search.invoke({"query": "domain=example.com"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 2
        assert len(result["data"]["results"]) == 2
        assert result["data"]["results"][0]["ip"] == "1.2.3.4"
        assert result["data"]["results"][0]["port"] == "443"

    @patch("fackel.tools.recon.fofa_tool.circuit_breaker")
    @patch("fackel.tools.recon.fofa_tool.get_session")
    @patch("fackel.tools.recon.fofa_tool.require_env", side_effect=["user@example.com", "fake-key"])
    def test_empty_results(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        api_response = {"error": False, "size": 0, "results": []}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = fofa_search.invoke({"query": "domain=nonexistent.example"})
        assert result["status"] == "ok"
        assert result["data"]["results"] == []

    @patch("fackel.tools.recon.fofa_tool.circuit_breaker")
    @patch("fackel.tools.recon.fofa_tool.get_session")
    @patch("fackel.tools.recon.fofa_tool.require_env", side_effect=["user@example.com", "fake-key"])
    def test_api_error_returns_tool_exception(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        api_response = {"error": True, "errmsg": "invalid query"}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = fofa_search.invoke({"query": "domain=example.com"})
        assert "invalid query" in result

    @patch("fackel.tools.recon.fofa_tool.circuit_breaker")
    @patch("fackel.tools.recon.fofa_tool.get_session")
    @patch("fackel.tools.recon.fofa_tool.require_env", side_effect=["user@example.com", "fake-key"])
    def test_account_error_shows_clear_message(self, _env, mock_session, mock_cb):
        """F-point exhaustion or invalid account gives an actionable message."""
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        api_response = {
            "error": True,
            "errmsg": "[820031] F点余额不足",
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = fofa_search.invoke({"query": "domain=example.com"})
        assert "account error" in result
        assert "F-point balance" in result

    @patch("fackel.tools.recon.fofa_tool.circuit_breaker")
    @patch("fackel.tools.recon.fofa_tool.get_session")
    @patch("fackel.tools.recon.fofa_tool.require_env", side_effect=["user@example.com", "fake-key"])
    def test_http_failure_returns_error(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        mock_session.return_value.get.side_effect = Exception("connection timeout")

        result = fofa_search.invoke({"query": "domain=example.com"})
        assert "connection timeout" in result

    @patch("fackel.tools.recon.fofa_tool.circuit_breaker")
    @patch("fackel.tools.recon.fofa_tool.get_session")
    @patch("fackel.tools.recon.fofa_tool.require_env", side_effect=["user@example.com", "fake-key"])
    def test_truncates_long_banners(self, _env, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        long_banner = "A" * 500
        api_response = {
            "error": False,
            "size": 1,
            "results": [
                [
                    "https://example.com",
                    "1.2.3.4",
                    "443",
                    "https",
                    "nginx",
                    "Example",
                    "example.com",
                    "Org",
                    long_banner,
                ],
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = fofa_search.invoke({"query": "domain=example.com"})
        assert len(result["data"]["results"][0]["banner"]) == 300
