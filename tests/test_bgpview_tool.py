"""Tests for bgpview_lookup tool — HTTP calls mocked via unittest.mock."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tools.recon.bgpview_tool import bgpview_lookup


def _ok_response(json_data: dict, status: int = 200) -> MagicMock:
    """Build a mock requests.Response with JSON payload."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


def _error_response(status: int) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.raise_for_status.side_effect = requests.HTTPError(f"{status} Server Error")
    return resp


class TestBgpviewLookupHappyPath:
    """Successful BGPView API responses."""

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_returns_parsed_data(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _ok_response(
            {
                "status": "ok",
                "data": {
                    "ip": "104.21.36.250",
                    "ptr_record": "104.21.36.250",
                    "prefixes": [
                        {
                            "prefix": "104.21.32.0/20",
                            "cidr": 20,
                            "asn": {
                                "asn": 13335,
                                "name": "CLOUDFLARENET",
                                "description": "Cloudflare, Inc.",
                                "country_code": "US",
                            },
                        },
                    ],
                    "rir_allocation": {
                        "rir_name": "ARIN",
                        "country_code": "US",
                        "date_allocated": "2014-03-28",
                    },
                },
            }
        )
        result = bgpview_lookup.invoke({"ip": "104.21.36.250"})
        assert result["status"] == "ok"
        assert result["tool"] == "bgpview_lookup"
        data = result["data"]
        assert data["ip"] == "104.21.36.250"
        assert data["asn"] == 13335
        assert data["asn_name"] == "CLOUDFLARENET"
        assert data["asn_description"] == "Cloudflare, Inc."
        assert data["prefix"] == "104.21.32.0/20"
        assert data["rir"] == "ARIN"

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_multiple_prefixes_picks_most_specific(self, mock_get: MagicMock) -> None:
        """When multiple prefixes exist, should pick the longest mask."""
        mock_get.return_value = _ok_response(
            {
                "status": "ok",
                "data": {
                    "ip": "1.2.3.4",
                    "prefixes": [
                        {
                            "prefix": "1.0.0.0/8",
                            "cidr": 8,
                            "asn": {
                                "asn": 100,
                                "name": "BROAD",
                                "description": "",
                                "country_code": "",
                            },
                        },
                        {
                            "prefix": "1.2.3.0/24",
                            "cidr": 24,
                            "asn": {
                                "asn": 300,
                                "name": "MOST-SPECIFIC",
                                "description": "Most Specific",
                                "country_code": "FR",
                            },
                        },
                        {
                            "prefix": "1.2.0.0/16",
                            "cidr": 16,
                            "asn": {
                                "asn": 200,
                                "name": "MEDIUM",
                                "description": "",
                                "country_code": "DE",
                            },
                        },
                    ],
                    "rir_allocation": {},
                },
            }
        )
        result = bgpview_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["asn"] == 300
        assert data["asn_name"] == "MOST-SPECIFIC"
        assert data["prefix"] == "1.2.3.0/24"
        assert data["cidr"] == 24

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_no_prefixes(self, mock_get: MagicMock) -> None:
        """IP with no announced prefixes — fields default gracefully."""
        mock_get.return_value = _ok_response(
            {
                "status": "ok",
                "data": {
                    "ip": "192.0.2.1",
                    "prefixes": [],
                    "rir_allocation": {"rir_name": "IANA"},
                },
            }
        )
        result = bgpview_lookup.invoke({"ip": "192.0.2.1"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["asn"] is None
        assert data["asn_name"] == ""
        assert data["prefix"] == ""
        assert data["rir"] == "IANA"


class TestBgpviewLookupErrors:
    """Error handling for BGPView API failures."""

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_http_error(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _error_response(500)
        result = bgpview_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "error"
        assert "request failed" in result["error"]

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_api_error_status(self, mock_get: MagicMock) -> None:
        """BGPView returns 200 but with status != 'ok'."""
        mock_get.return_value = _ok_response(
            {
                "status": "error",
                "status_message": "Invalid IP",
            }
        )
        result = bgpview_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "error"
        assert "Invalid IP" in result["error"]

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_non_json_response(self, mock_get: MagicMock) -> None:
        resp = _ok_response({})
        resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = resp
        result = bgpview_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "error"
        assert "non-JSON" in result["error"]

    @patch("tools.recon.bgpview_tool.requests.get")
    def test_connection_error(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        result = bgpview_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "error"
        assert "request failed" in result["error"]

    def test_rejects_invalid_ip(self) -> None:
        result = bgpview_lookup.invoke({"ip": "not-an-ip"})
        assert result["status"] == "error"

    def test_rejects_empty_input(self) -> None:
        result = bgpview_lookup.invoke({"ip": ""})
        assert result["status"] == "error"

    def test_rejects_domain(self) -> None:
        result = bgpview_lookup.invoke({"ip": "example.com"})
        assert result["status"] == "error"
