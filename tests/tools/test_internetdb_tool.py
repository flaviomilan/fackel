"""Tests for internetdb_lookup — Shodan InternetDB (free, key-less)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests
from langchain_core.messages import ToolMessage

from fackel.agents.orchestrator.extractors import extract_ips
from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.recon.internetdb_tool import internetdb_lookup


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestInternetDbLookup:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch("fackel.tools.recon.internetdb_tool.get_session")
    def test_returns_ports_cpes_vulns(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            {
                "ip": "1.1.1.1",
                "ports": [80, 443],
                "cpes": ["cpe:/a:nginx:nginx"],
                "vulns": ["CVE-2021-1234"],
                "hostnames": ["one.one.one.one"],
                "tags": ["cdn"],
            }
        )
        result = internetdb_lookup.invoke({"ip": "1.1.1.1"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["ip"] == "1.1.1.1"
        assert data["ports"] == [80, 443]
        assert "CVE-2021-1234" in data["vulns"]
        assert data["cpes"] == ["cpe:/a:nginx:nginx"]

    @patch("fackel.tools.recon.internetdb_tool.get_session")
    def test_404_returns_ok_empty(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"detail": "no info"}, status=404)
        result = internetdb_lookup.invoke({"ip": "8.8.8.8"})
        assert result["status"] == "ok"
        assert result["data"]["ports"] == []
        assert "no InternetDB data" in result["data"]["message"]

    @patch("fackel.tools.recon.internetdb_tool.get_session")
    def test_ip_picked_up_by_extractor(self, mock_gs: MagicMock) -> None:
        """The data.ip key must be extracted into routing state (parity)."""
        mock_gs.return_value.get.return_value = _resp(
            {"ip": "9.9.9.9", "ports": [], "cpes": [], "vulns": [], "hostnames": [], "tags": []}
        )
        result = internetdb_lookup.invoke({"ip": "9.9.9.9"})
        msg = ToolMessage(content=json.dumps(result), name="internetdb_lookup", tool_call_id="t")
        assert "9.9.9.9" in extract_ips([msg])

    def test_rejects_domain(self) -> None:
        result = internetdb_lookup.invoke({"ip": "example.com"})
        assert "internetdb_lookup" in result
