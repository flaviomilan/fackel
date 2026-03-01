"""Tests for formatting helpers."""

from __future__ import annotations

from fackel.formatting import (
    find_evaluation,
    format_tech_fingerprint,
    is_ipv6,
    serialize_findings,
)


class TestSerializeFindings:
    """Verify finding serialisation to Markdown."""

    def test_empty_findings(self):
        assert serialize_findings([]) == "No findings collected."

    def test_single_finding(self):
        findings = [{"phase": "osint", "title": "OSINT", "detail": "Found 3 subdomains"}]
        result = serialize_findings(findings)
        assert "## OSINT" in result
        assert "Found 3 subdomains" in result

    def test_multiple_findings_joined_with_separator(self):
        findings = [
            {"title": "First", "detail": "Detail 1"},
            {"title": "Second", "detail": "Detail 2"},
        ]
        result = serialize_findings(findings)
        assert "---" in result
        assert "## First" in result
        assert "## Second" in result

    def test_include_severity_tag(self):
        findings = [{"title": "Vuln", "detail": "XSS", "severity": "high"}]
        result = serialize_findings(findings, include_severity=True)
        assert "[severity: high]" in result

    def test_severity_tag_omitted_by_default(self):
        findings = [{"title": "Vuln", "detail": "XSS", "severity": "high"}]
        result = serialize_findings(findings)
        assert "[severity:" not in result

    def test_uses_phase_as_fallback_header(self):
        findings = [{"phase": "port_scan", "detail": "Open ports"}]
        result = serialize_findings(findings)
        assert "## port_scan" in result


class TestFormatTechFingerprint:
    """Verify tech fingerprint formatting."""

    def test_basic_fingerprint(self):
        fp = {"host": "example.com", "server": "nginx", "technologies": []}
        result = format_tech_fingerprint(fp)
        assert "example.com" in result
        assert "nginx" in result

    def test_with_technologies(self):
        fp = {"host": "example.com", "server": "nginx", "technologies": ["PHP", "WordPress"]}
        result = format_tech_fingerprint(fp)
        assert "PHP" in result
        assert "WordPress" in result

    def test_with_cdn(self):
        fp = {"host": "example.com", "server": "nginx", "technologies": [], "cdn": True}
        result = format_tech_fingerprint(fp)
        assert "CDN=yes" in result

    def test_with_waf(self):
        fp = {"host": "example.com", "server": "nginx", "technologies": [], "waf": "Cloudflare"}
        result = format_tech_fingerprint(fp)
        assert "WAF=Cloudflare" in result

    def test_bold_host(self):
        fp = {"host": "example.com", "server": "nginx", "technologies": []}
        result = format_tech_fingerprint(fp, bold_host=True)
        assert "**example.com**" in result

    def test_missing_server(self):
        fp = {"host": "example.com", "technologies": []}
        result = format_tech_fingerprint(fp)
        assert "server=?" in result

    def test_target_key_fallback(self):
        fp = {"target": "1.2.3.4", "server": "apache", "technologies": []}
        result = format_tech_fingerprint(fp)
        assert "1.2.3.4" in result


class TestFindEvaluation:
    """Verify evaluation lookup."""

    def test_finds_matching_phase(self):
        evals = [
            {"phase": "osint", "score": 0.8},
            {"phase": "port_scan", "score": 0.6},
        ]
        result = find_evaluation(evals, "port_scan")
        assert result is not None
        assert result["score"] == 0.6

    def test_returns_latest_match(self):
        evals = [
            {"phase": "osint", "score": 0.4},
            {"phase": "osint", "score": 0.9},
        ]
        result = find_evaluation(evals, "osint")
        assert result is not None
        assert result["score"] == 0.9

    def test_returns_none_when_not_found(self):
        evals = [{"phase": "osint", "score": 0.8}]
        result = find_evaluation(evals, "vuln_scan")
        assert result is None

    def test_empty_list(self):
        result = find_evaluation([], "osint")
        assert result is None


class TestIsIpv6:
    """Verify IPv6 detection."""

    def test_ipv6_address(self):
        assert is_ipv6("2001:db8::1") is True

    def test_ipv4_address(self):
        assert is_ipv6("192.168.1.1") is False

    def test_domain(self):
        assert is_ipv6("example.com") is False
