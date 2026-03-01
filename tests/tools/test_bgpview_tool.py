"""Tests for bgp_lookup tool — HTTP calls mocked via unittest.mock."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from tools.recon.bgpview_tool import _parse_holder, _parse_rir, bgp_lookup


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


class TestParseRir:
    """RIR extraction from RIPEstat block description."""

    def test_standard_format(self) -> None:
        assert _parse_rir({"desc": "ARIN (Status: ALLOCATED)"}) == "ARIN"

    def test_ripe_format(self) -> None:
        assert _parse_rir({"desc": "RIPE (Status: ALLOCATED PA)"}) == "RIPE"

    def test_apnic(self) -> None:
        assert _parse_rir({"desc": "APNIC (Status: ALLOCATED PORTABLE)"}) == "APNIC"

    def test_administered_by(self) -> None:
        assert _parse_rir({"desc": "Administered by ARIN"}) == "ARIN"

    def test_empty_desc(self) -> None:
        assert _parse_rir({"desc": ""}) == ""

    def test_no_parentheses(self) -> None:
        assert _parse_rir({"desc": "IANA"}) == "IANA"

    def test_empty_block(self) -> None:
        assert _parse_rir({}) == ""


class TestParseHolder:
    """Holder string splitting into short name and description."""

    def test_standard_holder(self) -> None:
        name, desc = _parse_holder("CLOUDFLARENET - Cloudflare, Inc.")
        assert name == "CLOUDFLARENET"
        assert desc == "Cloudflare, Inc."

    def test_no_separator(self) -> None:
        name, desc = _parse_holder("CLOUDFLARENET")
        assert name == "CLOUDFLARENET"
        assert desc == ""

    def test_empty_string(self) -> None:
        name, desc = _parse_holder("")
        assert name == ""
        assert desc == ""

    def test_multiple_dashes(self) -> None:
        name, desc = _parse_holder("AS-NAME - Some Org - Extra Info")
        assert name == "AS-NAME"
        assert desc == "Some Org - Extra Info"


class TestBgpLookupHappyPath:
    """Successful RIPEstat API responses."""

    @patch("tools.recon.bgpview_tool.get_session")
    def test_returns_parsed_data(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(
            {
                "data": {
                    "asns": [
                        {
                            "asn": 13335,
                            "holder": "CLOUDFLARENET - Cloudflare, Inc.",
                        },
                    ],
                    "resource": "104.21.32.0/20",
                    "block": {
                        "resource": "104.0.0.0/8",
                        "desc": "ARIN (Status: ALLOCATED)",
                        "name": "IANA IPv4 Address Space Registry",
                    },
                },
            }
        )
        result = bgp_lookup.invoke({"ip": "104.21.36.250"})
        assert result["status"] == "ok"
        assert result["tool"] == "bgp_lookup"
        data = result["data"]
        assert data["ip"] == "104.21.36.250"
        assert data["asn"] == 13335
        assert data["asn_name"] == "CLOUDFLARENET"
        assert data["asn_description"] == "Cloudflare, Inc."
        assert data["prefix"] == "104.21.32.0/20"
        assert data["cidr"] == 20
        assert data["rir"] == "ARIN"

    @patch("tools.recon.bgpview_tool.get_session")
    def test_multiple_asns_picks_first(self, mock_gs: MagicMock) -> None:
        """When multiple ASNs announce the prefix, the first one is used."""
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(
            {
                "data": {
                    "asns": [
                        {"asn": 100, "holder": "PRIMARY - Primary Inc."},
                        {"asn": 200, "holder": "SECONDARY - Secondary Inc."},
                    ],
                    "resource": "1.2.0.0/16",
                    "block": {"desc": "APNIC (Status: ALLOCATED)"},
                },
            }
        )
        result = bgp_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["asn"] == 100
        assert data["asn_name"] == "PRIMARY"
        assert data["rir"] == "APNIC"

    @patch("tools.recon.bgpview_tool.get_session")
    def test_no_asns(self, mock_gs: MagicMock) -> None:
        """IP with no announcing ASN — fields default gracefully."""
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(
            {
                "data": {
                    "asns": [],
                    "resource": "",
                    "block": {"desc": "IANA"},
                },
            }
        )
        result = bgp_lookup.invoke({"ip": "192.0.2.1"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["asn"] is None
        assert data["asn_name"] == ""
        assert data["prefix"] == ""
        assert data["cidr"] == 0
        assert data["rir"] == "IANA"

    @patch("tools.recon.bgpview_tool.get_session")
    def test_holder_without_separator(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(
            {
                "data": {
                    "asns": [{"asn": 999, "holder": "SIMPLENAME"}],
                    "resource": "10.0.0.0/8",
                    "block": {},
                },
            }
        )
        result = bgp_lookup.invoke({"ip": "10.0.0.1"})
        assert result["status"] == "ok"
        assert result["data"]["asn_name"] == "SIMPLENAME"
        assert result["data"]["asn_description"] == ""


class TestBgpLookupErrors:
    """Error handling for RIPEstat API failures."""

    def setup_method(self) -> None:
        reset_circuits()

    def teardown_method(self) -> None:
        reset_circuits()

    @patch("tools.recon.bgpview_tool.get_session")
    def test_http_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _error_response(500)
        result = bgp_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "request failed" in result.lower()

    @patch("tools.recon.bgpview_tool.get_session")
    def test_non_json_response(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        resp = _ok_response({})
        resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = resp
        result = bgp_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "non-json" in result.lower()

    @patch("tools.recon.bgpview_tool.get_session")
    def test_connection_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        result = bgp_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "request failed" in result.lower()

    @patch("tools.recon.bgpview_tool.get_session")
    def test_timeout_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = requests.Timeout("timed out")
        result = bgp_lookup.invoke({"ip": "1.2.3.4"})
        assert isinstance(result, str)
        assert "request failed" in result.lower()

    def test_rejects_invalid_ip(self) -> None:
        result = bgp_lookup.invoke({"ip": "not-an-ip"})
        assert isinstance(result, str)

    def test_rejects_empty_input(self) -> None:
        result = bgp_lookup.invoke({"ip": ""})
        assert isinstance(result, str)

    def test_rejects_domain(self) -> None:
        result = bgp_lookup.invoke({"ip": "example.com"})
        assert isinstance(result, str)
