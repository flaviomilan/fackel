"""Tests for abuseipdb_lookup — AbuseIPDB IP abuse reputation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.recon.abuseipdb_tool import abuseipdb_lookup


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestAbuseIPDBLookup:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "k"})
    @patch("fackel.tools.recon.abuseipdb_tool.get_session")
    def test_returns_score(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 88,
                    "totalReports": 42,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isTor": True,
                }
            }
        )
        result = abuseipdb_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["abuse_score"] == 88
        assert data["abuse_reports"] == 42
        assert data["abuse_tor"] is True

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "k"})
    @patch("fackel.tools.recon.abuseipdb_tool.get_session")
    def test_handles_missing_fields(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"data": {"ipAddress": "1.2.3.4"}})
        result = abuseipdb_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        assert result["data"]["abuse_score"] == 0

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "k"})
    @patch("fackel.tools.recon.abuseipdb_tool.get_session")
    def test_passes_key_header(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"data": {}})
        abuseipdb_lookup.invoke({"ip": "1.2.3.4"})
        kwargs = mock_gs.return_value.get.call_args.kwargs
        assert kwargs["headers"]["Key"] == "k"
        assert kwargs["params"]["ipAddress"] == "1.2.3.4"

    def test_missing_key_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        result = abuseipdb_lookup.invoke({"ip": "1.2.3.4"})
        assert "abuseipdb_lookup" in result

    def test_rejects_domain(self) -> None:
        result = abuseipdb_lookup.invoke({"ip": "example.com"})
        assert "abuseipdb_lookup" in result
