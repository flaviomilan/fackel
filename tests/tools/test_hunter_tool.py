"""Tests for hunter_email_search — Hunter.io email discovery."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.osint.hunter_tool import hunter_email_search


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestHunterEmailSearch:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch.dict("os.environ", {"HUNTER_API_KEY": "k"})
    @patch("fackel.tools.osint.hunter_tool.get_session")
    def test_discovers_emails_and_org(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "data": {
                    "domain": "example.com",
                    "organization": "Example Inc",
                    "emails": [
                        {
                            "value": "Ann@Example.com",
                            "first_name": "Ann",
                            "last_name": "Lee",
                            "position": "CTO",
                            "confidence": 95,
                            "type": "personal",
                        }
                    ],
                }
            }
        )
        result = hunter_email_search.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["organization"] == "Example Inc"
        assert data["count"] == 1
        assert data["emails"][0]["email"] == "ann@example.com"  # normalised
        assert data["emails"][0]["position"] == "CTO"

    @patch.dict("os.environ", {"HUNTER_API_KEY": "k"})
    @patch("fackel.tools.osint.hunter_tool.get_session")
    def test_passes_api_key(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"data": {"emails": []}})
        hunter_email_search.invoke({"domain": "example.com"})
        params = mock_gs.return_value.get.call_args.kwargs["params"]
        assert params["api_key"] == "k"
        assert params["domain"] == "example.com"

    def test_missing_key_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("HUNTER_API_KEY", raising=False)
        result = hunter_email_search.invoke({"domain": "example.com"})
        assert "hunter_email_search" in result

    def test_rejects_ip(self) -> None:
        result = hunter_email_search.invoke({"domain": "1.2.3.4"})
        assert "hunter_email_search" in result
