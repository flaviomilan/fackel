"""Tests for orchestrator node extraction helpers.

These test the pure extraction functions that parse ToolMessage payloads
into structured data for the graph state.
"""

from __future__ import annotations

import json

from langchain_core.messages import ToolMessage

from fackel.agents.orchestrator.extractors import (
    extract_historical_ips,
    extract_ip_classifications,
    extract_ips,
    extract_san_domains,
    extract_tech_fingerprints,
)


def _tool_msg(name: str, payload: dict) -> ToolMessage:
    """Build a ToolMessage with JSON content."""
    return ToolMessage(
        content=json.dumps(payload),
        name=name,
        tool_call_id="test",
    )


# ── Tech fingerprint extraction ───────────────────────────────────────────


class TestExtractTechFingerprints:
    """extract_tech_fingerprints from httpx_scan results."""

    def test_extracts_single_result(self) -> None:
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {
                    "results": [
                        {
                            "url": "https://example.com",
                            "host": "example.com",
                            "input": "example.com",
                            "status_code": 200,
                            "webserver": "nginx/1.25",
                            "title": "Example Domain",
                            "tech": ["Nginx", "React", "Webpack"],
                            "content_type": "text/html",
                            "cdn": True,
                            "waf": "Cloudflare",
                            "tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"},
                        }
                    ],
                },
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert len(fps) == 1
        fp = fps[0]
        assert fp["target"] == "https://example.com"
        assert fp["host"] == "example.com"
        assert fp["status_code"] == 200
        assert fp["server"] == "nginx/1.25"
        assert fp["title"] == "Example Domain"
        assert fp["technologies"] == ["Nginx", "React", "Webpack"]
        assert fp["cdn"] is True
        assert fp["waf"] == "Cloudflare"
        assert fp["tls"]["version"] == "TLSv1.3"

    def test_extracts_multiple_results(self) -> None:
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {
                    "results": [
                        {
                            "url": "https://example.com",
                            "host": "example.com",
                            "status_code": 200,
                            "webserver": "nginx",
                        },
                        {
                            "url": "https://api.example.com",
                            "host": "api.example.com",
                            "status_code": 200,
                            "webserver": "gunicorn",
                        },
                    ],
                },
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert len(fps) == 2
        hosts = {fp["host"] for fp in fps}
        assert hosts == {"example.com", "api.example.com"}

    def test_deduplicates_by_url(self) -> None:
        """Same URL from multiple httpx calls should be counted once."""
        msg1 = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {
                    "results": [
                        {"url": "https://example.com", "host": "example.com", "status_code": 200},
                    ]
                },
            },
        )
        msg2 = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {
                    "results": [
                        {"url": "https://example.com", "host": "example.com", "status_code": 301},
                    ]
                },
            },
        )
        fps = extract_tech_fingerprints([msg1, msg2])
        assert len(fps) == 1

    def test_ignores_error_results(self) -> None:
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "error",
                "error": "httpx binary not found",
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert fps == []

    def test_ignores_non_httpx_tools(self) -> None:
        msg = _tool_msg(
            "dns_resolve",
            {
                "tool": "dns_resolve",
                "status": "ok",
                "data": {"ips": ["1.2.3.4"]},
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert fps == []

    def test_handles_empty_results(self) -> None:
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {"results": []},
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert fps == []

    def test_handles_missing_optional_fields(self) -> None:
        """httpx result with minimal fields should still parse."""
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {
                    "results": [
                        {"url": "http://example.com:8080", "host": "example.com"},
                    ]
                },
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert len(fps) == 1
        fp = fps[0]
        assert fp["server"] == ""
        assert fp["technologies"] == []
        assert fp["cdn"] is False

    def test_tech_as_string(self) -> None:
        """Some httpx versions return tech as a single string."""
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {
                    "results": [
                        {"url": "https://example.com", "host": "example.com", "tech": "WordPress"},
                    ]
                },
            },
        )
        fps = extract_tech_fingerprints([msg])
        assert fps[0]["technologies"] == ["WordPress"]

    def test_empty_messages(self) -> None:
        assert extract_tech_fingerprints([]) == []


# ── IP classification extraction ──────────────────────────────────────────


class TestExtractIpClassifications:
    """extract_ip_classifications from ipinfo/bgp."""

    def test_ipinfo_cloudflare(self) -> None:
        msg = _tool_msg(
            "ipinfo_lookup",
            {
                "tool": "ipinfo_lookup",
                "status": "ok",
                "data": {
                    "ip": "104.21.36.250",
                    "org": "Cloudflare, Inc.",
                    "asn": "AS13335",
                    "hostname": "",
                    "anycast": True,
                    "city": "San Francisco",
                    "country": "US",
                },
            },
        )
        classes = extract_ip_classifications([msg], "example.com")
        assert len(classes) == 1
        assert classes[0]["ip"] == "104.21.36.250"
        assert classes[0]["ip_class"] == "cdn"

    def test_bgp_supplement(self) -> None:
        """RIPEstat BGP data supplements ipinfo with asn_name."""
        msg_ipinfo = _tool_msg(
            "ipinfo_lookup",
            {
                "tool": "ipinfo_lookup",
                "status": "ok",
                "data": {"ip": "1.2.3.4", "org": "SomeOrg", "asn": "AS12345"},
            },
        )
        msg_bgp = _tool_msg(
            "bgp_lookup",
            {
                "tool": "bgp_lookup",
                "status": "ok",
                "data": {
                    "ip": "1.2.3.4",
                    "asn_name": "AMAZON-AES",
                    "asn_description": "Amazon.com, Inc.",
                    "asn": 12345,
                },
            },
        )
        classes = extract_ip_classifications([msg_ipinfo, msg_bgp], "example.com")
        assert len(classes) == 1
        assert classes[0]["asn_name"] == "AMAZON-AES"

    def test_empty_messages(self) -> None:
        assert extract_ip_classifications([], "example.com") == []


# ── IP extraction ─────────────────────────────────────────────────────────


class TestExtractIps:
    """extract_ips — basic happy path."""

    def test_extracts_from_dns_resolve(self) -> None:
        msg = _tool_msg(
            "dns_resolve",
            {
                "tool": "dns_resolve",
                "status": "ok",
                "data": {"ips": ["1.2.3.4", "5.6.7.8"]},
            },
        )
        ips = extract_ips([msg])
        assert ips == ["1.2.3.4", "5.6.7.8"]

    def test_deduplicates(self) -> None:
        msg1 = _tool_msg(
            "dns_resolve",
            {
                "tool": "dns_resolve",
                "status": "ok",
                "data": {"ips": ["1.2.3.4"]},
            },
        )
        msg2 = _tool_msg(
            "shodan_lookup",
            {
                "tool": "shodan_lookup",
                "status": "ok",
                "data": {"ip": "1.2.3.4"},
            },
        )
        ips = extract_ips([msg1, msg2])
        assert ips == ["1.2.3.4"]

    def test_empty_messages(self) -> None:
        assert extract_ips([]) == []


# ── SAN domain extraction from tlscert ─────────────────────────────────────


class TestExtractSanDomains:
    """extract_san_domains from tlscert_lookup results."""

    def test_extracts_sans_matching_base_domain(self) -> None:
        msg = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "ok",
                "data": {
                    "subject_cn": "example.com",
                    "san_domains": [
                        "example.com",
                        "www.example.com",
                        "api.example.com",
                        "staging.example.com",
                    ],
                },
            },
        )
        subs = extract_san_domains([msg], "example.com")
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "staging.example.com" in subs
        # base domain itself is excluded
        assert "example.com" not in subs

    def test_ignores_unrelated_domains(self) -> None:
        msg = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "ok",
                "data": {
                    "san_domains": [
                        "example.com",
                        "www.example.com",
                        "other-domain.net",
                        "cdn.cloudflare.com",
                    ],
                },
            },
        )
        subs = extract_san_domains([msg], "example.com")
        assert "other-domain.net" not in subs
        assert "cdn.cloudflare.com" not in subs
        assert "www.example.com" in subs

    def test_deduplicates_across_messages(self) -> None:
        msg1 = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "ok",
                "data": {"san_domains": ["www.example.com", "api.example.com"]},
            },
        )
        msg2 = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "ok",
                "data": {"san_domains": ["www.example.com", "mail.example.com"]},
            },
        )
        subs = extract_san_domains([msg1, msg2], "example.com")
        assert subs.count("www.example.com") == 1
        assert "api.example.com" in subs
        assert "mail.example.com" in subs

    def test_skips_error_status(self) -> None:
        msg = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "error",
                "error": "Connection refused",
            },
        )
        assert extract_san_domains([msg], "example.com") == []

    def test_skips_non_tlscert_tools(self) -> None:
        msg = _tool_msg(
            "httpx_scan",
            {
                "tool": "httpx_scan",
                "status": "ok",
                "data": {"san_domains": ["sneaky.example.com"]},
            },
        )
        assert extract_san_domains([msg], "example.com") == []

    def test_filters_reverse_ptr_subdomains(self) -> None:
        msg = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "ok",
                "data": {
                    "san_domains": [
                        "www.example.com",
                        "200-210-75-128.example.com",
                    ],
                },
            },
        )
        subs = extract_san_domains([msg], "example.com")
        assert "www.example.com" in subs
        assert "200-210-75-128.example.com" not in subs

    def test_empty_messages(self) -> None:
        assert extract_san_domains([], "example.com") == []

    def test_returns_sorted(self) -> None:
        msg = _tool_msg(
            "tlscert_lookup",
            {
                "tool": "tlscert_lookup",
                "status": "ok",
                "data": {
                    "san_domains": ["z.example.com", "a.example.com", "m.example.com"],
                },
            },
        )
        subs = extract_san_domains([msg], "example.com")
        assert subs == sorted(subs)


# ── Historical IP extraction from SecurityTrails ────────────────────────────────────


class TestExtractHistoricalIps:
    """extract_historical_ips from securitytrails_history results."""

    def test_extracts_ips_not_in_current(self) -> None:
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "ok",
                "data": {
                    "a_records": [
                        {
                            "value": "93.184.216.34",
                            "first_seen": "2020-01-01",
                            "last_seen": "2022-06-30",
                            "org": "Edgecast",
                        },
                        {
                            "value": "104.21.36.250",
                            "first_seen": "2022-07-01",
                            "last_seen": "2025-01-01",
                            "org": "Cloudflare",
                        },
                    ],
                    "mx_records": [],
                    "ns_records": [],
                },
            },
        )
        current_ips = ["104.21.36.250", "172.67.201.157"]
        historical = extract_historical_ips([msg], current_ips)
        assert historical == ["93.184.216.34"]

    def test_excludes_current_ips(self) -> None:
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "ok",
                "data": {
                    "a_records": [
                        {
                            "value": "104.21.36.250",
                            "first_seen": "2022-07-01",
                            "last_seen": "2025-01-01",
                            "org": "Cloudflare",
                        },
                    ],
                    "mx_records": [],
                    "ns_records": [],
                },
            },
        )
        historical = extract_historical_ips([msg], ["104.21.36.250"])
        assert historical == []

    def test_deduplicates(self) -> None:
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "ok",
                "data": {
                    "a_records": [
                        {
                            "value": "93.184.216.34",
                            "first_seen": "2020-01-01",
                            "last_seen": "2021-01-01",
                            "org": "",
                        },
                        {
                            "value": "93.184.216.34",
                            "first_seen": "2021-01-02",
                            "last_seen": "2022-01-01",
                            "org": "",
                        },
                    ],
                    "mx_records": [],
                    "ns_records": [],
                },
            },
        )
        historical = extract_historical_ips([msg], [])
        assert historical == ["93.184.216.34"]

    def test_ignores_mx_and_ns_records(self) -> None:
        """Only A records are extracted as IPs."""
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "ok",
                "data": {
                    "a_records": [],
                    "mx_records": [
                        {"value": "mail.example.com", "first_seen": "", "last_seen": "", "org": ""}
                    ],
                    "ns_records": [
                        {"value": "ns1.example.com", "first_seen": "", "last_seen": "", "org": ""}
                    ],
                },
            },
        )
        historical = extract_historical_ips([msg], [])
        assert historical == []

    def test_skips_error_status(self) -> None:
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "error",
                "error": "API key missing",
            },
        )
        assert extract_historical_ips([msg], []) == []

    def test_skips_non_securitytrails_tools(self) -> None:
        msg = _tool_msg(
            "dns_resolve",
            {
                "tool": "dns_resolve",
                "status": "ok",
                "data": {"a_records": [{"value": "93.184.216.34"}]},
            },
        )
        assert extract_historical_ips([msg], []) == []

    def test_validates_ip_format(self) -> None:
        """Invalid IPs in records are silently skipped."""
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "ok",
                "data": {
                    "a_records": [
                        {"value": "not-an-ip", "first_seen": "", "last_seen": "", "org": ""},
                        {"value": "93.184.216.34", "first_seen": "", "last_seen": "", "org": ""},
                    ],
                    "mx_records": [],
                    "ns_records": [],
                },
            },
        )
        historical = extract_historical_ips([msg], [])
        assert historical == ["93.184.216.34"]

    def test_empty_messages(self) -> None:
        assert extract_historical_ips([], []) == []

    def test_empty_a_records(self) -> None:
        msg = _tool_msg(
            "securitytrails_history",
            {
                "tool": "securitytrails_history",
                "status": "ok",
                "data": {"a_records": [], "mx_records": [], "ns_records": []},
            },
        )
        assert extract_historical_ips([msg], []) == []
