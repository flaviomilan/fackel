"""Tests for otx_passive_dns tool — HTTP calls mocked via unittest.mock."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from tools.recon.otx_tool import otx_passive_dns


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


_PASSIVE_DNS_RESPONSE = {
    "passive_dns": [
        {
            "address": "93.184.216.34",
            "hostname": "example.com.",
            "record_type": "A",
            "first": "2020-03-15",
            "last": "2025-01-10",
            "asn": "AS15133",
        },
        {
            "address": "2606:2800:220:1:248:1893:25c8:1946",
            "hostname": "example.com",
            "record_type": "AAAA",
            "first": "2021-06-01",
            "last": "2025-01-10",
            "asn": "AS15133",
        },
        {
            "address": "www.example.com",
            "hostname": "example.com",
            "record_type": "CNAME",
            "first": "2019-01-01",
            "last": "2024-12-31",
            "asn": "",
        },
    ],
}


class TestOtxPassiveDnsHappyPath:
    """Successful OTX API responses."""

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    @patch("tools.recon.otx_tool.get_session")
    def test_returns_parsed_records(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(_PASSIVE_DNS_RESPONSE)

        result = otx_passive_dns.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["tool"] == "otx_passive_dns"
        data = result["data"]
        assert data["count"] == 3
        assert len(data["records"]) == 3

        first = data["records"][0]
        assert first["address"] == "93.184.216.34"
        assert first["hostname"] == "example.com"
        assert first["record_type"] == "A"
        assert first["first_seen"] == "2020-03-15"
        assert first["last_seen"] == "2025-01-10"
        assert first["asn"] == "AS15133"

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    @patch("tools.recon.otx_tool.get_session")
    def test_passes_api_key_in_header(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"passive_dns": []})

        otx_passive_dns.invoke({"domain": "example.com"})

        call_args = mock_get.call_args
        assert call_args.kwargs["headers"]["X-OTX-API-KEY"] == "test-otx-key"

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    @patch("tools.recon.otx_tool.get_session")
    def test_empty_records(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"passive_dns": []})

        result = otx_passive_dns.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["count"] == 0
        assert result["data"]["records"] == []

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    @patch("tools.recon.otx_tool.get_session")
    def test_deduplicates_records(self, mock_gs: MagicMock) -> None:
        """Duplicate (address, record_type, hostname) combos are filtered."""
        mock_get = mock_gs.return_value.get
        duped = {
            "passive_dns": [
                {
                    "address": "93.184.216.34",
                    "hostname": "example.com",
                    "record_type": "A",
                    "first": "2020-01-01",
                    "last": "2025-01-01",
                    "asn": "",
                },
                {
                    "address": "93.184.216.34",
                    "hostname": "example.com",
                    "record_type": "A",
                    "first": "2020-01-01",
                    "last": "2025-01-01",
                    "asn": "",
                },
            ],
        }
        mock_get.return_value = _ok_response(duped)

        result = otx_passive_dns.invoke({"domain": "example.com"})

        assert result["data"]["count"] == 1


class TestOtxPassiveDnsErrors:
    """Error handling."""

    def setup_method(self) -> None:
        reset_circuits()

    def teardown_method(self) -> None:
        reset_circuits()

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    @patch("tools.recon.otx_tool.get_session")
    def test_http_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = requests.HTTPError("403 Forbidden")

        result = otx_passive_dns.invoke({"domain": "example.com"})

        assert isinstance(result, str)
        assert "403" in result

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    @patch("tools.recon.otx_tool.get_session")
    def test_non_json_response(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        resp = MagicMock(spec=requests.Response)
        resp.raise_for_status.return_value = None
        resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = resp

        result = otx_passive_dns.invoke({"domain": "example.com"})

        assert isinstance(result, str)
        assert "non-json" in result.lower()

    def test_missing_api_key(self) -> None:
        """Returns error when OTX_API_KEY is not set."""
        original = os.environ.pop("OTX_API_KEY", None)
        try:
            result = otx_passive_dns.invoke({"domain": "example.com"})
            assert isinstance(result, str)
            assert "OTX_API_KEY" in result
        finally:
            if original is not None:
                os.environ["OTX_API_KEY"] = original


class TestOtxPassiveDnsValidation:
    """Input validation via guard_target."""

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    def test_rejects_ip_address(self) -> None:
        result = otx_passive_dns.invoke({"domain": "1.2.3.4"})
        assert isinstance(result, str)

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    def test_rejects_empty_domain(self) -> None:
        result = otx_passive_dns.invoke({"domain": ""})
        assert isinstance(result, str)

    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key"})
    def test_rejects_shell_metacharacters(self) -> None:
        result = otx_passive_dns.invoke({"domain": "example.com; rm -rf /"})
        assert isinstance(result, str)
