"""Tests for shodan_lookup — Shodan passive intelligence."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.recon.shodan_tool import shodan_lookup


class TestShodanLookup:
    """Verify Shodan API integration for IP and query modes."""

    @patch("tools.recon.shodan_tool.shodan.Shodan")
    @patch("tools.recon.shodan_tool.require_env", return_value="test-key")
    def test_ip_host_lookup(self, _env, mock_shodan_cls):
        mock_api = MagicMock()
        mock_shodan_cls.return_value = mock_api
        mock_api.host.return_value = {
            "ip_str": "93.184.216.34",
            "org": "Edgecast",
            "isp": "Edgecast Inc.",
            "os": "Linux",
            "hostnames": ["example.com"],
            "ports": [80, 443],
            "city": "Norwell",
            "country_name": "United States",
            "last_update": "2026-03-01T12:00:00",
            "vulns": ["CVE-2021-44228"],
            "data": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.24.0",
                    "data": "HTTP/1.1 200 OK",
                    "_shodan": {"module": "https"},
                },
            ],
        }

        result = shodan_lookup.invoke({"query": "93.184.216.34"})

        assert result["status"] == "ok"
        assert result["data"]["ip"] == "93.184.216.34"
        assert result["data"]["org"] == "Edgecast"
        assert "CVE-2021-44228" in result["data"]["vulns"]
        assert len(result["data"]["services"]) == 1
        assert result["data"]["services"][0]["port"] == 443
        assert result["data"]["services"][0]["product"] == "nginx"

    @patch("tools.recon.shodan_tool.shodan.Shodan")
    @patch("tools.recon.shodan_tool.require_env", return_value="test-key")
    def test_search_query_mode(self, _env, mock_shodan_cls):
        mock_api = MagicMock()
        mock_shodan_cls.return_value = mock_api
        mock_api.search.return_value = {
            "total": 1,
            "matches": [
                {
                    "ip_str": "1.2.3.4",
                    "port": 80,
                    "org": "TestOrg",
                    "data": "Apache/2.4",
                    "product": "Apache",
                },
            ],
        }

        result = shodan_lookup.invoke({"query": "hostname:example.com"})

        assert result["status"] == "ok"
        assert result["data"]["total"] == 1
        assert len(result["data"]["matches"]) == 1
        assert result["data"]["matches"][0]["ip"] == "1.2.3.4"

    @patch("tools.recon.shodan_tool.shodan.Shodan")
    @patch("tools.recon.shodan_tool.require_env", return_value="test-key")
    def test_api_error_raises_tool_exception(self, _env, mock_shodan_cls):
        mock_api = MagicMock()
        mock_shodan_cls.return_value = mock_api
        mock_api.host.side_effect = Exception("Invalid API key")

        result = shodan_lookup.invoke({"query": "93.184.216.34"})
        assert "invalid api key" in result.lower()

    @patch("tools.recon.shodan_tool.shodan.Shodan")
    @patch("tools.recon.shodan_tool.require_env", return_value="test-key")
    def test_host_empty_services(self, _env, mock_shodan_cls):
        mock_api = MagicMock()
        mock_shodan_cls.return_value = mock_api
        mock_api.host.return_value = {
            "ip_str": "203.0.113.1",
            "org": None,
            "isp": None,
            "os": None,
            "hostnames": [],
            "ports": [],
            "data": [],
        }

        result = shodan_lookup.invoke({"query": "203.0.113.1"})

        assert result["status"] == "ok"
        assert result["data"]["services"] == []
        assert result["data"]["ports"] == []

    @patch("tools.recon.shodan_tool.shodan.Shodan")
    @patch("tools.recon.shodan_tool.require_env", return_value="test-key")
    def test_search_empty_matches(self, _env, mock_shodan_cls):
        mock_api = MagicMock()
        mock_shodan_cls.return_value = mock_api
        mock_api.search.return_value = {"total": 0, "matches": []}

        result = shodan_lookup.invoke({"query": "hostname:noresults.test"})

        assert result["status"] == "ok"
        assert result["data"]["total"] == 0
        assert result["data"]["matches"] == []
