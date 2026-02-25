"""Tests for securitytrails_history tool — HTTP calls mocked via unittest.mock."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tools.recon.securitytrails_tool import securitytrails_history


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


# Sample SecurityTrails API responses
_A_HISTORY = {
    "records": [
        {
            "first_seen": "2020-01-15",
            "last_seen": "2022-06-30",
            "values": [
                {"ip": "93.184.216.34", "ip_organization": "Edgecast"},
            ],
        },
        {
            "first_seen": "2022-07-01",
            "last_seen": "2025-01-01",
            "values": [
                {"ip": "104.21.36.250", "ip_organization": "Cloudflare, Inc."},
                {"ip": "172.67.201.157", "ip_organization": "Cloudflare, Inc."},
            ],
        },
    ],
}

_MX_HISTORY = {
    "records": [
        {
            "first_seen": "2019-05-01",
            "last_seen": "2023-12-31",
            "values": [
                {"host": "mail.example.com", "ip_organization": ""},
            ],
        },
    ],
}

_NS_HISTORY = {
    "records": [
        {
            "first_seen": "2018-01-01",
            "last_seen": "2025-01-01",
            "values": [
                {"nameserver": "ns1.cloudflare.com", "ip_organization": "Cloudflare"},
            ],
        },
    ],
}


class TestSecurityTrailsHappyPath:
    """Successful SecurityTrails API responses."""

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    @patch("tools.recon.securitytrails_tool.get_session")
    def test_returns_all_record_types(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        # Three sequential calls: A, MX, NS
        mock_get.side_effect = [
            _ok_response(_A_HISTORY),
            _ok_response(_MX_HISTORY),
            _ok_response(_NS_HISTORY),
        ]

        result = securitytrails_history.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["tool"] == "securitytrails_history"
        data = result["data"]

        # A records
        assert len(data["a_records"]) == 3
        assert data["a_records"][0]["value"] == "93.184.216.34"
        assert data["a_records"][0]["org"] == "Edgecast"
        assert data["a_records"][0]["first_seen"] == "2020-01-15"
        assert data["a_records"][1]["value"] == "104.21.36.250"

        # MX records
        assert len(data["mx_records"]) == 1
        assert data["mx_records"][0]["value"] == "mail.example.com"

        # NS records
        assert len(data["ns_records"]) == 1
        assert data["ns_records"][0]["value"] == "ns1.cloudflare.com"

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    @patch("tools.recon.securitytrails_tool.get_session")
    def test_passes_api_key_in_header(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"records": []})

        securitytrails_history.invoke({"domain": "example.com"})

        # All three calls should use the APIKEY header
        for call in mock_get.call_args_list:
            assert call.kwargs["headers"]["APIKEY"] == "test-key-123"

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    @patch("tools.recon.securitytrails_tool.get_session")
    def test_empty_records(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"records": []})

        result = securitytrails_history.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["a_records"] == []
        assert result["data"]["mx_records"] == []
        assert result["data"]["ns_records"] == []

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    @patch("tools.recon.securitytrails_tool.get_session")
    def test_strips_trailing_dot(self, mock_gs: MagicMock) -> None:
        """Nameservers/hosts with trailing dots are normalised."""
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = [
            _ok_response({"records": []}),
            _ok_response({"records": []}),
            _ok_response(
                {
                    "records": [
                        {
                            "first_seen": "2020-01-01",
                            "last_seen": "2025-01-01",
                            "values": [{"nameserver": "ns1.example.com.", "ip_organization": ""}],
                        }
                    ],
                }
            ),
        ]

        result = securitytrails_history.invoke({"domain": "example.com"})
        assert result["data"]["ns_records"][0]["value"] == "ns1.example.com"


class TestSecurityTrailsErrors:
    """Error handling."""

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    @patch("tools.recon.securitytrails_tool.get_session")
    def test_partial_failure_still_returns_ok(self, mock_gs: MagicMock) -> None:
        """If one record type fails, others still succeed."""
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = [
            _error_response(429),  # A records rate-limited
            _ok_response(_MX_HISTORY),
            _ok_response(_NS_HISTORY),
        ]

        result = securitytrails_history.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        # A records contain error entry
        assert len(result["data"]["a_records"]) == 1
        assert "error" in result["data"]["a_records"][0]
        # MX and NS still populated
        assert len(result["data"]["mx_records"]) == 1
        assert len(result["data"]["ns_records"]) == 1

    @patch.dict("os.environ", {}, clear=False)
    def test_missing_api_key(self) -> None:
        """Returns error when SECURITYTRAILS_API_KEY is not set."""
        import os

        original = os.environ.pop("SECURITYTRAILS_API_KEY", None)
        try:
            result = securitytrails_history.invoke({"domain": "example.com"})
            assert isinstance(result, str)
            assert "SECURITYTRAILS_API_KEY" in result
        finally:
            if original is not None:
                os.environ["SECURITYTRAILS_API_KEY"] = original


class TestSecurityTrailsValidation:
    """Input validation via guard_target."""

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    def test_rejects_ip_address(self) -> None:
        result = securitytrails_history.invoke({"domain": "1.2.3.4"})
        assert isinstance(result, str)

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    def test_rejects_empty_domain(self) -> None:
        result = securitytrails_history.invoke({"domain": ""})
        assert isinstance(result, str)

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "test-key-123"})
    def test_rejects_shell_metacharacters(self) -> None:
        result = securitytrails_history.invoke({"domain": "example.com; rm -rf /"})
        assert isinstance(result, str)
