"""Tests for nmap_scanner — port/service scanning with version detection."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.tools import ToolException

from tools.scanning.nmap_scanner import (
    _build_scan_args,
    _build_scan_result,
    _extract_vulnerabilities,
    _is_root,
    _parse_hostscript,
    _parse_os_info,
    _parse_services,
    nmap_port_scan,
)


# ── Pure helper tests ──────────────────────────────────────────────────────


class TestIsRoot:
    """Verify _is_root without side-effects."""

    @patch("os.geteuid", return_value=0)
    def test_returns_true_for_root(self, _euid):
        assert _is_root() is True

    @patch("os.geteuid", return_value=1000)
    def test_returns_false_for_regular_user(self, _euid):
        assert _is_root() is False


class TestBuildScanArgs:
    """Verify CLI argument construction for each scan type."""

    def test_quick_scan_no_vuln_scripts(self):
        args = _build_scan_args("quick", "", False)
        joined = " ".join(args)
        assert "-sV" in args
        assert "vulners" not in joined
        assert "vuln" not in joined

    def test_default_scan_includes_vuln_scripts(self):
        args = _build_scan_args("default", "", False)
        joined = " ".join(args)
        assert "vulners" in joined

    def test_deep_scan_all_ports(self):
        args = _build_scan_args("deep", "", False)
        assert "-p-" in args

    def test_deep_scan_with_ports_no_dashp(self):
        args = _build_scan_args("deep", "80,443", False)
        assert "-p-" not in args
        assert "-p" in args
        assert "80,443" in args

    def test_ports_appended(self):
        args = _build_scan_args("default", "22,80", False)
        assert "-p" in args
        idx = args.index("-p")
        assert args[idx + 1] == "22,80"

    def test_skip_host_discovery(self):
        args = _build_scan_args("default", "", True)
        assert "-Pn" in args

    @patch("tools.scanning.nmap_scanner._is_root", return_value=True)
    def test_root_adds_os_detection(self, _root):
        args = _build_scan_args("default", "", False)
        assert "-O" in args
        assert "--osscan-guess" in args


class TestExtractVulnerabilities:
    """Verify CVE extraction from script output."""

    def test_no_scripts_returns_empty(self):
        assert _extract_vulnerabilities({}) == []

    def test_vulners_cve_extraction(self):
        service = {
            "script": {
                "vulners": "CVE-2021-44228 10.0\nCVE-2023-1234 7.5",
            }
        }
        vulns = _extract_vulnerabilities(service)
        assert len(vulns) == 2
        assert vulns[0]["id"] == "CVE-2021-44228"
        assert vulns[0]["cvss"] == 10.0
        assert vulns[0]["source"] == "vulners"

    def test_vulscan_deduplication(self):
        service = {
            "script": {
                "vulners": "CVE-2021-44228 10.0",
                "vulscan": "CVE-2021-44228 CVE-2023-9999",
            }
        }
        vulns = _extract_vulnerabilities(service)
        ids = [v["id"] for v in vulns]
        assert ids.count("CVE-2021-44228") == 1
        assert "CVE-2023-9999" in ids

    def test_nse_vuln_script_detection(self):
        service = {
            "script": {
                "http-vuln-cve2017-5638": "State: VULNERABLE\nApache Struts2",
            }
        }
        vulns = _extract_vulnerabilities(service)
        assert len(vulns) == 1
        assert vulns[0]["source"] == "nse_script"


class TestParseOsInfo:
    """Verify OS detection parsing."""

    def test_empty_host_returns_empty_lists(self):
        nm = MagicMock()
        nm.__getitem__ = MagicMock(return_value={})
        result = _parse_os_info(nm, "192.168.1.1")
        assert result["os_matches"] == []
        assert result["os_classes"] == []

    def test_osmatch_extraction(self):
        nm = MagicMock()
        nm.__getitem__ = MagicMock(
            return_value={
                "osmatch": [{"name": "Linux 5.4", "accuracy": "95"}],
            }
        )
        result = _parse_os_info(nm, "192.168.1.1")
        assert len(result["os_matches"]) == 1
        assert result["os_matches"][0]["name"] == "Linux 5.4"
        assert result["os_matches"][0]["accuracy"] == 95


class TestParseHostscript:
    """Verify hostscript parsing."""

    def test_no_hostscript_returns_empty(self):
        nm = MagicMock()
        nm.__getitem__ = MagicMock(return_value={})
        result = _parse_hostscript(nm, "192.168.1.1")
        assert result == {}

    def test_hostscript_extraction(self):
        nm = MagicMock()
        nm.__getitem__ = MagicMock(
            return_value={
                "hostscript": [
                    {"id": "smb-os-discovery", "output": "Windows Server 2019"},
                ],
            }
        )
        result = _parse_hostscript(nm, "192.168.1.1")
        assert "smb-os-discovery" in result


class TestParseServices:
    """Verify per-port service parsing and counters."""

    def test_open_ports_counted(self):
        nm = MagicMock()
        host_mock = MagicMock()
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.__getitem__ = MagicMock(
            return_value={
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "nginx",
                    "version": "1.18",
                    "extrainfo": "",
                    "cpe": "",
                },
                443: {
                    "state": "open",
                    "name": "https",
                    "product": "nginx",
                    "version": "1.18",
                    "extrainfo": "",
                    "cpe": "",
                },
            }
        )
        nm.__getitem__ = MagicMock(return_value=host_mock)

        services, summary = _parse_services(nm, "192.168.1.1")
        assert summary["open_ports"] == 2
        assert summary["total_ports_scanned"] == 2


class TestNmapPortScan:
    """Integration-level tests for the tool entry point."""

    @patch("tools.scanning.nmap_scanner.nmap.PortScanner")
    @patch("tools.scanning.nmap_scanner.require_binary", return_value=None)
    def test_invalid_scan_type_returns_error(self, _bin, _nm):
        result = nmap_port_scan.invoke({"host": "example.com", "scan_type": "invalid"})
        assert "invalid scan_type" in result

    @patch("tools.scanning.nmap_scanner.nmap.PortScanner")
    @patch("tools.scanning.nmap_scanner.require_binary", return_value=None)
    def test_no_hosts_found_returns_error(self, _bin, mock_scanner_cls):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []
        mock_scanner_cls.return_value = mock_nm

        result = nmap_port_scan.invoke({"host": "example.com"})
        assert "Host may be down" in result

    @patch("tools.scanning.nmap_scanner.nmap.PortScanner")
    @patch("tools.scanning.nmap_scanner.require_binary", return_value=None)
    def test_successful_scan_returns_data(self, _bin, mock_scanner_cls):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["example.com"]
        host_mock = MagicMock()
        host_mock.state.return_value = "up"
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock.__contains__ = MagicMock(return_value=False)
        host_mock.__getitem__ = MagicMock(return_value={})

        mock_nm.__getitem__ = MagicMock(return_value=host_mock)
        mock_scanner_cls.return_value = mock_nm

        result = nmap_port_scan.invoke({"host": "example.com"})
        assert result["status"] == "ok"
        assert result["tool"] == "nmap_port_scan"
