"""Tests for netlas_lookup — Netlas scan-database host search."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.recon.netlas_tool import netlas_lookup


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestNetlasLookup:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch.dict("os.environ", {"NETLAS_API_KEY": "k"})
    @patch("fackel.tools.recon.netlas_tool.get_session")
    def test_extracts_hosts(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "items": [
                    {"data": {"ip": "1.2.3.4", "host": "www.example.com", "port": 443}},
                    {"data": {"ip": "5.6.7.8", "domain": "api.example.com", "port": 80}},
                ]
            }
        )
        result = netlas_lookup.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        hosts = result["data"]["hosts"]
        assert {h["ip"] for h in hosts} == {"1.2.3.4", "5.6.7.8"}
        assert any(h["hostname"] == "www.example.com" for h in hosts)
        assert result["data"]["count"] == 2

    @patch.dict("os.environ", {"NETLAS_API_KEY": "k"})
    @patch("fackel.tools.recon.netlas_tool.get_session")
    def test_dedupes_and_skips_empty(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "items": [
                    {"data": {"ip": "1.2.3.4", "host": "www.example.com"}},
                    {"data": {"ip": "1.2.3.4", "host": "www.example.com"}},
                    {"data": {}},  # no ip/hostname — skipped
                ]
            }
        )
        result = netlas_lookup.invoke({"domain": "example.com"})
        assert result["data"]["count"] == 1

    @patch.dict("os.environ", {"NETLAS_API_KEY": "k"})
    @patch("fackel.tools.recon.netlas_tool.get_session")
    def test_passes_key_header(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"items": []})
        netlas_lookup.invoke({"domain": "example.com"})
        kwargs = mock_gs.return_value.get.call_args.kwargs
        assert kwargs["headers"]["X-API-Key"] == "k"
        assert "domain:example.com" in kwargs["params"]["q"]

    def test_missing_key_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("NETLAS_API_KEY", raising=False)
        result = netlas_lookup.invoke({"domain": "example.com"})
        assert "netlas_lookup" in result

    def test_rejects_private_ip(self) -> None:
        result = netlas_lookup.invoke({"domain": "10.0.0.1"})
        assert "netlas_lookup" in result
