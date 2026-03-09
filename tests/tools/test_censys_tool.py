"""Tests for censys_lookup — Censys host/service search."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.recon.censys_tool import censys_lookup


class TestCensysLookup:
    """Verify Censys API integration and result parsing."""

    @patch("tools.recon.censys_tool.CensysHosts")
    @patch("tools.recon.censys_tool.require_env", side_effect=["test-id", "test-secret"])
    def test_parses_host_results(self, _env, mock_hosts_cls):
        mock_client = MagicMock()
        mock_hosts_cls.return_value = mock_client
        mock_client.search.return_value = iter(
            [
                {
                    "ip": "93.184.216.34",
                    "services": [
                        {
                            "port": 443,
                            "transport_protocol": "tcp",
                            "service_name": "HTTP",
                        },
                        {
                            "port": 80,
                            "transport_protocol": "tcp",
                            "service_name": "HTTP",
                        },
                    ],
                },
            ]
        )

        result = censys_lookup.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        hosts = result["data"]["hosts"]
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "93.184.216.34"
        assert len(hosts[0]["services"]) == 2
        assert hosts[0]["services"][0]["port"] == 443

    @patch("tools.recon.censys_tool.CensysHosts")
    @patch("tools.recon.censys_tool.require_env", side_effect=["test-id", "test-secret"])
    def test_empty_results(self, _env, mock_hosts_cls):
        mock_client = MagicMock()
        mock_hosts_cls.return_value = mock_client
        mock_client.search.return_value = iter([])

        result = censys_lookup.invoke({"domain": "noresults.example.com"})

        assert result["status"] == "ok"
        assert result["data"]["hosts"] == []

    @patch("tools.recon.censys_tool.CensysHosts")
    @patch("tools.recon.censys_tool.require_env", side_effect=["test-id", "test-secret"])
    def test_api_error_raises_tool_exception(self, _env, mock_hosts_cls):
        mock_client = MagicMock()
        mock_hosts_cls.return_value = mock_client
        mock_client.search.side_effect = Exception("API rate limit exceeded")

        result = censys_lookup.invoke({"domain": "example.com"})
        assert "rate limit" in result.lower()

    @patch("tools.recon.censys_tool.CensysHosts")
    @patch("tools.recon.censys_tool.require_env", side_effect=["test-id", "test-secret"])
    def test_host_without_services_key(self, _env, mock_hosts_cls):
        mock_client = MagicMock()
        mock_hosts_cls.return_value = mock_client
        mock_client.search.return_value = iter([{"ip": "10.0.0.1"}])

        result = censys_lookup.invoke({"domain": "nosvcs.example.com"})

        assert result["status"] == "ok"
        assert result["data"]["hosts"][0]["ip"] == "10.0.0.1"
        assert result["data"]["hosts"][0]["services"] == []
