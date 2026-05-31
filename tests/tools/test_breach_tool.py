"""Tests for breach_lookup — LeakCheck breach database lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.osint.breach_tool import breach_lookup


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestBreachLookup:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch.dict("os.environ", {"LEAKCHECK_API_KEY": "k"})
    @patch("fackel.tools.osint.breach_tool.get_session")
    def test_returns_breaches(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "success": True,
                "found": 2,
                "result": [
                    {"source": {"name": "Collection1", "breach_date": "2019-01"}},
                    {"source": {"name": "LinkedIn", "breach_date": "2012-05"}},
                ],
            }
        )
        result = breach_lookup.invoke({"email": "jane@example.com"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["found"] == 2
        names = {b["name"] for b in data["breaches"]}
        assert names == {"Collection1", "LinkedIn"}

    @patch.dict("os.environ", {"LEAKCHECK_API_KEY": "k"})
    @patch("fackel.tools.osint.breach_tool.get_session")
    def test_dedupes_sources(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "result": [
                    {"source": {"name": "Dup"}},
                    {"source": {"name": "dup"}},
                ]
            }
        )
        result = breach_lookup.invoke({"email": "jane@example.com"})
        assert result["data"]["found"] == 1

    @patch.dict("os.environ", {"LEAKCHECK_API_KEY": "k"})
    @patch("fackel.tools.osint.breach_tool.get_session")
    def test_passes_key_and_normalizes_email(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"result": []})
        breach_lookup.invoke({"email": "Jane@Example.com"})
        call = mock_gs.return_value.get.call_args
        assert call.kwargs["headers"]["X-API-Key"] == "k"
        assert "jane@example.com" in call.args[0]

    def test_missing_key_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("LEAKCHECK_API_KEY", raising=False)
        result = breach_lookup.invoke({"email": "jane@example.com"})
        assert "breach_lookup" in result

    def test_invalid_email_errors(self) -> None:
        result = breach_lookup.invoke({"email": "not-an-email"})
        assert "breach_lookup" in result
