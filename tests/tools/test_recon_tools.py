"""Tests for remaining recon tools — dns_resolver, crtsh, dnsdumpster,
reverse_dns, shodan, subfinder, virustotal, censys."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import requests

from tools.recon.crtsh_tool import crtsh_subdomain_enum
from tools.recon.dns_resolver import dns_resolve
from tools.recon.reverse_dns_tool import reverse_dns_lookup
from tools.recon.subfinder_tool import subfinder_enum


class TestDnsResolve:
    """Verify DNS resolution tool."""

    @patch("tools.recon.dns_resolver.socket.getaddrinfo")
    def test_resolves_domain(self, mock_getaddr):
        mock_getaddr.return_value = [
            (socket.AF_INET, 0, 0, "", ("1.2.3.4", 0)),
            (socket.AF_INET, 0, 0, "", ("5.6.7.8", 0)),
        ]
        result = dns_resolve.invoke({"target": "example.com"})
        assert result["status"] == "ok"
        assert "1.2.3.4" in result["data"]["ips"]
        assert result["data"]["type"] == "domain"

    def test_validates_ip_address(self):
        result = dns_resolve.invoke({"target": "203.0.113.1"})
        assert result["status"] == "ok"
        assert result["data"]["type"] == "ip"
        assert "203.0.113.1" in result["data"]["ips"]

    @patch("tools.recon.dns_resolver.socket.getaddrinfo", side_effect=socket.gaierror("no host"))
    def test_resolution_failure_returns_error(self, _mock):
        result = dns_resolve.invoke({"target": "nonexistent.example"})
        assert "dns_resolve" in result


class TestCrtShSubdomainEnum:
    """Verify crt.sh tool."""

    @patch("tools.recon.crtsh_tool.circuit_breaker")
    @patch("tools.recon.crtsh_tool.get_session")
    def test_extracts_subdomains(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        entries = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com\nsub3.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = entries
        mock_resp.raise_for_status = MagicMock()
        mock_session.return_value.get.return_value = mock_resp

        result = crtsh_subdomain_enum.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] >= 2
        subs = result["data"]["subdomains"]
        assert "sub1.example.com" in subs

    @patch("tools.recon.crtsh_tool.circuit_breaker")
    @patch("tools.recon.crtsh_tool._fetch_crtsh")
    def test_404_returns_empty(self, mock_fetch, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        resp_404 = MagicMock()
        resp_404.status_code = 404
        error = requests.HTTPError("404", response=resp_404)
        mock_fetch.side_effect = error

        result = crtsh_subdomain_enum.invoke({"domain": "example.com"})
        assert result["data"]["count"] == 0


class TestReverseDnsLookup:
    """Verify reverse DNS and reverse IP lookup."""

    @patch("tools.recon.reverse_dns_tool.get_session")
    @patch("tools.recon.reverse_dns_tool.socket.gethostbyaddr")
    def test_ptr_record_found(self, mock_gethostbyaddr, mock_session):
        mock_gethostbyaddr.return_value = ("mail.example.com", [], ["1.2.3.4"])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "example.com\nother.com"
        mock_session.return_value.get.return_value = mock_resp

        result = reverse_dns_lookup.invoke({"ip": "1.2.3.4"})
        assert result["status"] == "ok"
        assert result["data"]["ptr_hostname"] == "mail.example.com"
        assert len(result["data"]["shared_domains"]) == 2

    @patch("tools.recon.reverse_dns_tool.get_session")
    @patch("tools.recon.reverse_dns_tool.socket.gethostbyaddr", side_effect=socket.herror())
    def test_no_ptr_record(self, _gethostbyaddr, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_session.return_value.get.return_value = mock_resp

        result = reverse_dns_lookup.invoke({"ip": "1.2.3.4"})
        assert result["data"]["ptr_hostname"] is None

    @patch("tools.recon.reverse_dns_tool.get_session")
    @patch("tools.recon.reverse_dns_tool.socket.gethostbyaddr", side_effect=socket.herror())
    def test_hackertarget_error_response_ignored(self, _gethostbyaddr, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "error check your search"
        mock_session.return_value.get.return_value = mock_resp

        result = reverse_dns_lookup.invoke({"ip": "1.2.3.4"})
        assert result["data"]["shared_domains"] == []


class TestSubfinderEnum:
    """Verify subfinder CLI and result parsing."""

    @patch("tools.recon.subfinder_tool.run_command")
    @patch("tools.recon.subfinder_tool.require_binary", return_value=None)
    def test_basic_command_construction(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        subfinder_enum.invoke({"domain": "example.com"})
        cmd = mock_run.call_args[0][0]
        assert "subfinder" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd

    @patch("tools.recon.subfinder_tool.run_command")
    @patch("tools.recon.subfinder_tool.require_binary", return_value=None)
    def test_all_sources_flag(self, _bin, mock_run):
        mock_run.return_value = (0, "", "")
        subfinder_enum.invoke({"domain": "example.com", "all_sources": True})
        cmd = mock_run.call_args[0][0]
        assert "-all" in cmd

    @patch("tools.recon.subfinder_tool.run_command")
    @patch("tools.recon.subfinder_tool.require_binary", return_value=None)
    def test_jsonl_parsing(self, _bin, mock_run):
        lines = (
            '{"host": "sub1.example.com", "source": "crtsh"}\n'
            '{"host": "sub2.example.com", "source": "censys"}\n'
        )
        mock_run.return_value = (0, lines, "")
        result = subfinder_enum.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 2
        assert "crtsh" in result["data"]["sources"]

    @patch("tools.recon.subfinder_tool.run_command")
    @patch("tools.recon.subfinder_tool.require_binary", return_value=None)
    def test_plain_text_fallback(self, _bin, mock_run):
        mock_run.return_value = (0, "sub1.example.com\nsub2.example.com\n", "")
        result = subfinder_enum.invoke({"domain": "example.com"})
        assert result["data"]["count"] == 2

    @patch("tools.recon.subfinder_tool.run_command")
    @patch("tools.recon.subfinder_tool.require_binary", return_value=None)
    def test_deduplication(self, _bin, mock_run):
        lines = (
            '{"host": "sub1.example.com", "source": "crtsh"}\n'
            '{"host": "sub1.example.com", "source": "censys"}\n'
        )
        mock_run.return_value = (0, lines, "")
        result = subfinder_enum.invoke({"domain": "example.com"})
        assert result["data"]["count"] == 1

    @patch("tools.recon.subfinder_tool.run_command", side_effect=Exception("timeout"))
    @patch("tools.recon.subfinder_tool.require_binary", return_value=None)
    def test_command_failure_returns_error(self, _bin, _run):
        result = subfinder_enum.invoke({"domain": "example.com"})
        assert "timeout" in result
