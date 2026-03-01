"""Tests for whois_lookup — WHOIS with RDAP fallback."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from tools.recon.whois import (
    _build_rdap_data,
    _extract_rdap_event,
    _extract_rdap_nameservers,
    _extract_rdap_registrar,
    _rdap_server_for_tld,
    whois_lookup,
)

SAMPLE_RDAP = {
    "ldhName": "example.info",
    "status": ["client transfer prohibited", "client delete prohibited"],
    "entities": [
        {
            "roles": ["registrar"],
            "handle": "146",
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "GoDaddy.com, LLC"],
                ],
            ],
        },
    ],
    "nameservers": [
        {"ldhName": "ns1.cloudflare.com"},
        {"ldhName": "ns2.cloudflare.com"},
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2022-08-31T13:38:25Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-31T13:38:25Z"},
        {"eventAction": "last changed", "eventDate": "2025-08-30T11:23:03Z"},
    ],
}


class TestExtractRdapRegistrar:
    def test_extracts_from_vcard_fn(self):
        assert _extract_rdap_registrar(SAMPLE_RDAP) == "GoDaddy.com, LLC"

    def test_returns_handle_if_no_vcard(self):
        data = {
            "entities": [
                {"roles": ["registrar"], "handle": "REG-99"},
            ],
        }
        assert _extract_rdap_registrar(data) == "REG-99"

    def test_returns_none_when_no_registrar(self):
        data = {"entities": [{"roles": ["abuse"]}]}
        assert _extract_rdap_registrar(data) is None

    def test_returns_none_when_no_entities(self):
        assert _extract_rdap_registrar({}) is None


class TestExtractRdapNameservers:
    def test_extracts_nameservers(self):
        ns = _extract_rdap_nameservers(SAMPLE_RDAP)
        assert ns == ["ns1.cloudflare.com", "ns2.cloudflare.com"]

    def test_empty_when_no_nameservers(self):
        assert _extract_rdap_nameservers({}) == []

    def test_skips_entries_without_ldhname(self):
        data = {"nameservers": [{"objectClassName": "nameserver"}, {"ldhName": "ns1.example.com"}]}
        assert _extract_rdap_nameservers(data) == ["ns1.example.com"]


class TestExtractRdapEvent:
    def test_extracts_registration(self):
        assert _extract_rdap_event(SAMPLE_RDAP, "registration") == "2022-08-31T13:38:25Z"

    def test_extracts_expiration(self):
        assert _extract_rdap_event(SAMPLE_RDAP, "expiration") == "2026-08-31T13:38:25Z"

    def test_returns_none_for_unknown_action(self):
        assert _extract_rdap_event(SAMPLE_RDAP, "transfer") is None

    def test_returns_none_when_no_events(self):
        assert _extract_rdap_event({}, "registration") is None


class TestBuildRdapData:
    def test_full_rdap_response(self):
        data = _build_rdap_data(SAMPLE_RDAP)
        assert data["registrar"] == "GoDaddy.com, LLC"
        assert data["name_servers"] == ["ns1.cloudflare.com", "ns2.cloudflare.com"]
        assert data["creation_date"] == "2022-08-31T13:38:25Z"
        assert data["expiration_date"] == "2026-08-31T13:38:25Z"
        assert data["parsed"] is True
        assert data["source"] == "rdap"
        assert data["status"] == ["client transfer prohibited", "client delete prohibited"]

    def test_empty_rdap_response(self):
        data = _build_rdap_data({})
        assert data["parsed"] is False
        assert data["source"] == "rdap"
        assert data["registrar"] is None
        assert data["name_servers"] == []

    def test_raw_truncated_to_2000(self):
        big = {"ldhName": "x" * 3000}
        data = _build_rdap_data(big)
        assert len(data["raw"]) <= 2000


class TestRdapServerForTld:
    def test_finds_server_from_bootstrap(self):
        bootstrap = {
            "services": [
                [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["info"], ["https://rdap.identitydigital.services/rdap/"]],
            ],
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(bootstrap).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("tools.recon.whois.urllib.request.urlopen", return_value=mock_resp):
            url = _rdap_server_for_tld("info")
            assert url == "https://rdap.identitydigital.services/rdap"

    def test_returns_none_for_unknown_tld(self):
        bootstrap = {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(bootstrap).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("tools.recon.whois.urllib.request.urlopen", return_value=mock_resp):
            assert _rdap_server_for_tld("xyz") is None

    def test_returns_none_on_network_error(self):
        with patch("tools.recon.whois.urllib.request.urlopen", side_effect=OSError):
            assert _rdap_server_for_tld("info") is None


class TestWhoisLookupTraditional:
    """When python-whois succeeds, RDAP should be skipped."""

    @patch("tools.recon.whois._whois_query")
    def test_traditional_whois_success(self, mock_query):
        record = MagicMock()
        record.registrar = "GoDaddy.com, LLC"
        record.name_servers = ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
        record.creation_date = "2020-01-01"
        record.expiration_date = "2025-01-01"
        record.__str__ = lambda self: "raw whois text"
        mock_query.return_value = record

        result = whois_lookup.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["registrar"] == "GoDaddy.com, LLC"
        assert result["data"]["source"] == "whois"
        assert result["data"]["parsed"] is True

    @patch("tools.recon.whois._whois_query")
    def test_traditional_whois_empty_falls_through(self, mock_query):
        """When whois returns no parsed data, result still has parsed=False."""
        record = MagicMock()
        record.registrar = None
        record.name_servers = None
        record.creation_date = None
        record.expiration_date = None
        record.__str__ = lambda self: "terms of use only"
        mock_query.return_value = record

        with patch("tools.recon.whois._rdap_query", return_value=None):
            result = whois_lookup.invoke({"domain": "example.info"})
            assert isinstance(result, str)


class TestWhoisLookupRdapFallback:
    """When python-whois fails, RDAP should provide data."""

    @patch("tools.recon.whois._whois_query", side_effect=Exception("WHOIS failed"))
    @patch("tools.recon.whois._rdap_query", return_value=SAMPLE_RDAP)
    def test_rdap_fallback_on_whois_failure(self, _rdap, _whois):
        result = whois_lookup.invoke({"domain": "example.info"})

        assert result["status"] == "ok"
        assert result["data"]["source"] == "rdap"
        assert result["data"]["registrar"] == "GoDaddy.com, LLC"
        assert result["data"]["name_servers"] == ["ns1.cloudflare.com", "ns2.cloudflare.com"]
        assert result["data"]["creation_date"] == "2022-08-31T13:38:25Z"
        assert result["data"]["parsed"] is True

    @patch("tools.recon.whois._whois_query", side_effect=Exception("WHOIS failed"))
    @patch("tools.recon.whois._rdap_query", return_value=None)
    def test_both_fail_returns_error(self, _rdap, _whois):
        result = whois_lookup.invoke({"domain": "example.xyz"})

        assert isinstance(result, str)
        assert "no data" in result.lower()


class TestWhoisInputValidation:
    def test_empty_domain_rejected(self):
        result = whois_lookup.invoke({"domain": ""})
        assert isinstance(result, str)

    def test_ip_address_rejected(self):
        result = whois_lookup.invoke({"domain": "1.2.3.4"})
        assert isinstance(result, str)

    def test_url_extracts_host(self):
        """guard_target for DOMAIN type should extract host from URL."""
        with (
            patch("tools.recon.whois._whois_query", side_effect=Exception("fail")),
            patch("tools.recon.whois._rdap_query", return_value=SAMPLE_RDAP),
        ):
            result = whois_lookup.invoke({"domain": "https://example.info/path"})
            assert result["status"] == "ok"
