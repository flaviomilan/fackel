"""Tests for parameter sanitizers — ports, severity, tags validators."""

import pytest

from fackel.tooling import sanitize_ports, sanitize_severity, sanitize_tags


class TestSanitizePorts:
    """Port string validation for nmap/naabu."""

    @pytest.mark.parametrize("value,expected", [
        ("80", "80"),
        ("80,443", "80,443"),
        ("80,443,8000-9000", "80,443,8000-9000"),
        ("22, 80, 443", "22,80,443"),
        ("1-65535", "1-65535"),
        ("", ""),
        ("  ", ""),
    ])
    def test_valid_ports(self, value: str, expected: str) -> None:
        result, err = sanitize_ports(value)
        assert err is None
        assert result == expected

    @pytest.mark.parametrize("value", [
        "80; rm -rf /",
        "80 --script-args=evil",
        "abc",
        "80,443,notaport",
        "-p 80",
        "80|cat /etc/passwd",
    ])
    def test_rejects_invalid_ports(self, value: str) -> None:
        _, err = sanitize_ports(value)
        assert err is not None


class TestSanitizeSeverity:
    """Severity filter validation for nuclei/testssl."""

    @pytest.mark.parametrize("value,expected", [
        ("critical", "critical"),
        ("critical,high", "critical,high"),
        ("HIGH, MEDIUM", "high,medium"),
        ("", ""),
        ("  ", ""),
    ])
    def test_valid_severities(self, value: str, expected: str) -> None:
        result, err = sanitize_severity(value)
        assert err is None
        assert result == expected

    @pytest.mark.parametrize("value", [
        "critical; rm -rf /",
        "notaseverity",
        "high,fake",
    ])
    def test_rejects_invalid_severity(self, value: str) -> None:
        _, err = sanitize_severity(value)
        assert err is not None


class TestSanitizeTags:
    """Tag string validation for nuclei."""

    @pytest.mark.parametrize("value,expected", [
        ("cve", "cve"),
        ("cve,wordpress", "cve,wordpress"),
        ("CVE, XSS, SQLI", "cve,xss,sqli"),
        ("", ""),
    ])
    def test_valid_tags(self, value: str, expected: str) -> None:
        result, err = sanitize_tags(value)
        assert err is None
        assert result == expected

    @pytest.mark.parametrize("value", [
        "cve; evil",
        "tag$(whoami)",
        "a|b",
    ])
    def test_rejects_invalid_tags(self, value: str) -> None:
        _, err = sanitize_tags(value)
        assert err is not None
