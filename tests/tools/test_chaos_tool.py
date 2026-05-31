"""Tests for chaos_enum — ProjectDiscovery Chaos subdomain enumeration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.recon.chaos_tool import chaos_enum


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestChaosEnum:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch.dict("os.environ", {"CHAOS_API_KEY": "k"})
    @patch("fackel.tools.recon.chaos_tool.get_session")
    def test_builds_fqdns(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {"domain": "example.com", "subdomains": ["www", "mail", "api"]}
        )
        result = chaos_enum.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        subs = result["data"]["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert result["data"]["count"] == 3

    @patch.dict("os.environ", {"CHAOS_API_KEY": "k"})
    @patch("fackel.tools.recon.chaos_tool.get_session")
    def test_dedupes_and_skips_empty(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"subdomains": ["www", "www", "", "@"]})
        result = chaos_enum.invoke({"domain": "example.com"})
        subs = result["data"]["subdomains"]
        assert subs.count("www.example.com") == 1
        # "@" maps to the apex; "" is skipped
        assert "example.com" in subs

    @patch.dict("os.environ", {"CHAOS_API_KEY": "k"})
    @patch("fackel.tools.recon.chaos_tool.get_session")
    def test_passes_authorization_header(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"subdomains": []})
        chaos_enum.invoke({"domain": "example.com"})
        headers = mock_gs.return_value.get.call_args.kwargs["headers"]
        assert headers["Authorization"] == "k"

    def test_missing_key_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("CHAOS_API_KEY", raising=False)
        result = chaos_enum.invoke({"domain": "example.com"})
        assert "chaos_enum" in result

    def test_rejects_ip(self) -> None:
        result = chaos_enum.invoke({"domain": "1.2.3.4"})
        assert "chaos_enum" in result
