"""Tests for greynoise_lookup — GreyNoise Community IP reputation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.recon.greynoise_tool import greynoise_lookup


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestGreyNoiseLookup:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch.dict("os.environ", {"GREYNOISE_API_KEY": "k"})
    @patch("fackel.tools.recon.greynoise_tool.get_session")
    def test_returns_reputation(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "ip": "1.2.3.4",
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "ScannerCo",
            }
        )
        result = greynoise_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["gn_noise"] is True
        assert data["gn_classification"] == "malicious"
        assert data["gn_actor"] == "ScannerCo"

    @patch.dict("os.environ", {"GREYNOISE_API_KEY": "k"})
    @patch("fackel.tools.recon.greynoise_tool.get_session")
    def test_404_not_observed_is_ok(self, mock_gs: MagicMock) -> None:
        # 404 must NOT raise — it is a valid "IP not observed" answer.
        resp = _resp(
            {"ip": "1.2.3.4", "noise": False, "riot": False, "message": "not observed"},
            status=404,
        )
        resp.raise_for_status.side_effect = AssertionError("must not be called on 404")
        mock_gs.return_value.get.return_value = resp
        result = greynoise_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        assert result["data"]["gn_noise"] is False

    @patch.dict("os.environ", {"GREYNOISE_API_KEY": "k"})
    @patch("fackel.tools.recon.greynoise_tool.get_session")
    def test_passes_key_header(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"ip": "1.2.3.4"})
        greynoise_lookup.invoke({"ip": "1.2.3.4"})
        headers = mock_gs.return_value.get.call_args.kwargs["headers"]
        assert headers["key"] == "k"

    def test_missing_key_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
        result = greynoise_lookup.invoke({"ip": "1.2.3.4"})
        assert "greynoise_lookup" in result

    def test_rejects_domain(self) -> None:
        result = greynoise_lookup.invoke({"ip": "example.com"})
        assert "greynoise_lookup" in result
