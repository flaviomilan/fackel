"""Tests for ipinfo_lookup tool — HTTP calls mocked via unittest.mock."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from tools.recon.ipinfo_tool import ipinfo_lookup


def _ok_response(json_data: dict, status: int = 200) -> MagicMock:
    """Build a mock requests.Response with JSON payload."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


def _error_response(status: int, body: str = "") -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.raise_for_status.side_effect = requests.HTTPError(f"{status} Server Error")
    return resp


class TestIpinfoLookupHappyPath:
    """Successful ipinfo.io responses."""

    @patch("tools.recon.ipinfo_tool.get_session")
    def test_returns_parsed_data(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(
            {
                "ip": "104.21.36.250",
                "hostname": "104.21.36.250",
                "city": "San Francisco",
                "region": "California",
                "country": "US",
                "org": "AS13335 Cloudflare, Inc.",
                "anycast": True,
            }
        )
        result = ipinfo_lookup.invoke({"ip": "104.21.36.250"})
        assert result["status"] == "ok"
        assert result["tool"] == "ipinfo_lookup"
        data = result["data"]
        assert data["ip"] == "104.21.36.250"
        assert data["org"] == "Cloudflare, Inc."
        assert data["asn"] == "AS13335"
        assert data["country"] == "US"
        assert data["anycast"] is True

    @patch("tools.recon.ipinfo_tool.get_session")
    def test_org_without_asn_prefix(self, mock_gs: MagicMock) -> None:
        """When ipinfo returns org without AS prefix."""
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(
            {
                "ip": "1.2.3.4",
                "org": "Some ISP LLC",
                "city": "Berlin",
                "region": "Berlin",
                "country": "DE",
            }
        )
        result = ipinfo_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["org"] == "Some ISP LLC"
        assert data["asn"] == ""

    @patch("tools.recon.ipinfo_tool.get_session")
    def test_minimal_response(self, mock_gs: MagicMock) -> None:
        """ipinfo returns only IP — optional fields default gracefully."""
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"ip": "198.51.100.1"})
        result = ipinfo_lookup.invoke({"ip": "198.51.100.1"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["ip"] == "198.51.100.1"
        assert data["org"] == ""
        assert data["asn"] == ""
        assert data["anycast"] is False


class TestIpinfoLookupErrors:
    """Error handling for ipinfo.io failures."""

    def setup_method(self) -> None:
        reset_circuits()

    def teardown_method(self) -> None:
        reset_circuits()

    @patch("tools.recon.ipinfo_tool.get_session")
    def test_http_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _error_response(429)
        result = ipinfo_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "request failed" in result.lower()

    @patch("tools.recon.ipinfo_tool.get_session")
    def test_non_json_response(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        resp = _ok_response({})
        resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = resp
        result = ipinfo_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "non-json" in result.lower()

    @patch("tools.recon.ipinfo_tool.get_session")
    def test_connection_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        result = ipinfo_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "request failed" in result.lower()

    def test_rejects_invalid_ip(self) -> None:
        result = ipinfo_lookup.invoke({"ip": "not-an-ip"})
        assert isinstance(result, str)

    def test_rejects_empty_input(self) -> None:
        result = ipinfo_lookup.invoke({"ip": ""})
        assert isinstance(result, str)

    def test_rejects_domain(self) -> None:
        result = ipinfo_lookup.invoke({"ip": "example.com"})
        assert isinstance(result, str)
