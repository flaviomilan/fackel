"""Tests for maigret_scan — username → social-account discovery."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from fackel.tools.osint.maigret_tool import maigret_scan

_SAMPLE_OUTPUT = """\
[*] Checking username janedoe on:
[+] GitHub: https://github.com/janedoe
[+] Twitter: https://twitter.com/janedoe
[-] Reddit: not found
[+] GitHub: https://github.com/janedoe
"""


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setenv("FACKEL_ENABLE_MAIGRET", "1")
    yield


class TestMaigretScan:
    @patch("fackel.tools.osint.maigret_tool.require_binary", lambda *a: None)
    @patch("fackel.tools.osint.maigret_tool.run_command")
    def test_parses_found_accounts(self, mock_run) -> None:
        mock_run.return_value = (0, _SAMPLE_OUTPUT, "")
        result = maigret_scan.invoke({"username": "janedoe"})
        assert result["status"] == "ok"
        data = result["data"]
        # Two unique accounts (the duplicate GitHub line is deduped).
        assert data["count"] == 2
        urls = {a["url"] for a in data["accounts"]}
        assert urls == {
            "https://github.com/janedoe",
            "https://twitter.com/janedoe",
        }
        assert data["username"] == "janedoe"

    @patch("fackel.tools.osint.maigret_tool.require_binary", lambda *a: None)
    @patch("fackel.tools.osint.maigret_tool.run_command")
    def test_no_accounts_returns_empty(self, mock_run) -> None:
        mock_run.return_value = (0, "[*] nothing found\n", "")
        result = maigret_scan.invoke({"username": "janedoe"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 0

    def test_disabled_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("FACKEL_ENABLE_MAIGRET", raising=False)
        result = maigret_scan.invoke({"username": "janedoe"})
        assert "FACKEL_ENABLE_MAIGRET" in result

    @patch("fackel.tools.osint.maigret_tool.require_binary", lambda *a: None)
    def test_rejects_invalid_username(self) -> None:
        result = maigret_scan.invoke({"username": "bad name!&"})
        assert "maigret_scan" in result
