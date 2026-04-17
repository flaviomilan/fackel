"""Tests for dnsx_resolve — bulk DNS resolution + wildcard filtering."""

from __future__ import annotations

import json
from unittest.mock import patch

from langchain_core.messages import ToolMessage

from fackel.agents.orchestrator.extractors import extract_ips, extract_subdomains
from fackel.agents.orchestrator.translators import translate_phase_messages
from fackel.domain import InformationType
from fackel.tools.recon.dnsx_tool import dnsx_resolve


class TestDnsxResolve:
    @patch("fackel.tools.recon.dnsx_tool.run_command")
    @patch("fackel.tools.recon.dnsx_tool.require_binary", return_value=None)
    def test_resolves_and_shapes_hosts(self, _bin, mock_run) -> None:
        jsonl = (
            '{"host":"www.example.com","a":["1.2.3.4"]}\n'
            '{"host":"api.example.com","a":["5.6.7.8","9.9.9.9"]}\n'
        )
        mock_run.return_value = (0, jsonl, "")
        result = dnsx_resolve.invoke(
            {
                "hosts": ["www.example.com", "api.example.com", "dead.example.com"],
                "wildcard_domain": "example.com",
            }
        )
        assert result["status"] == "ok"
        data = result["data"]
        pairs = {(h["hostname"], h["ip"]) for h in data["hosts"]}
        assert ("www.example.com", "1.2.3.4") in pairs
        assert ("api.example.com", "5.6.7.8") in pairs
        assert ("api.example.com", "9.9.9.9") in pairs
        assert "dead.example.com" in data["unresolved"]
        assert data["resolved"] == 2

    @patch("fackel.tools.recon.dnsx_tool.run_command")
    @patch("fackel.tools.recon.dnsx_tool.require_binary", return_value=None)
    def test_parity_extractor_and_translator(self, _bin, mock_run) -> None:
        """Both pipelines must extract the same hosts/IPs from the hosts[] shape."""
        mock_run.return_value = (0, '{"host":"www.example.com","a":["1.2.3.4"]}\n', "")
        result = dnsx_resolve.invoke(
            {"hosts": ["www.example.com"], "wildcard_domain": "example.com"}
        )
        msg = ToolMessage(content=json.dumps(result), name="dnsx_resolve", tool_call_id="t")

        assert "1.2.3.4" in extract_ips([msg])
        assert "www.example.com" in extract_subdomains([msg], "example.com")

        _execs, cands = translate_phase_messages(
            [msg], phase="osint", scan_id="t", target="example.com"
        )
        ips = {c.normalized_value for c in cands if c.type == InformationType.IP_ADDRESS}
        subs = {c.normalized_value for c in cands if c.type == InformationType.SUBDOMAIN}
        assert ips == {"1.2.3.4"}
        assert subs == {"www.example.com"}

    @patch("fackel.tools.recon.dnsx_tool.require_binary", return_value=None)
    def test_no_valid_hosts_returns_ok(self, _bin) -> None:
        result = dnsx_resolve.invoke({"hosts": ["not a domain", "also bad"]})
        assert result["status"] == "ok"
        assert result["data"]["hosts"] == []

    @patch("fackel.tools.recon.dnsx_tool.run_command")
    @patch("fackel.tools.recon.dnsx_tool.require_binary", return_value=None)
    def test_command_failure_returns_error(self, _bin, mock_run) -> None:
        mock_run.return_value = (1, "", "resolution failed")
        result = dnsx_resolve.invoke({"hosts": ["www.example.com"]})
        assert "resolution failed" in result
