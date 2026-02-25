"""Shared fixtures for the fackel test suite."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

# ── HTTP response mock factories ───────────────────────────────────────────


@pytest.fixture()
def ok_response():
    """Factory: build a mock ``requests.Response`` with a JSON payload.

    Usage::

        def test_something(ok_response):
            mock_resp = ok_response({"key": "value"})
    """

    def _make(json_data: dict[str, Any], status: int = 200) -> MagicMock:
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status
        resp.json.return_value = json_data
        resp.raise_for_status.return_value = None
        return resp

    return _make


@pytest.fixture()
def error_response():
    """Factory: build a mock ``requests.Response`` that raises on ``raise_for_status``.

    Usage::

        def test_error(error_response):
            mock_resp = error_response(500)
    """

    def _make(status: int, body: str = "") -> MagicMock:
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status
        resp.text = body
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status} Server Error")
        return resp

    return _make


# ── API key environment fixtures ───────────────────────────────────────────


@pytest.fixture()
def otx_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set ``OTX_API_KEY`` in the environment for OTX tool tests."""
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")


@pytest.fixture()
def securitytrails_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set ``SECURITYTRAILS_API_KEY`` in the environment for SecurityTrails tests."""
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key-123")
