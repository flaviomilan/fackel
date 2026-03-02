"""Tests for IP infrastructure classifier — pure function, no I/O."""

import pytest

from fackel.tooling.ip_classifier import IpClass, classify_ip


class TestClassifyIpByCdn:
    """CDN detection via ASN, org name, and anycast flag."""

    @pytest.mark.parametrize(
        "asn,org,expected",
        [
            (13335, "Cloudflare, Inc.", "cdn"),
            ("AS13335", "Cloudflare, Inc.", "cdn"),
            (20940, "Akamai Technologies", "cdn"),
            (54113, "Fastly, Inc.", "cdn"),
            (13249, "Incapsula Inc.", "cdn"),
            (30148, "Sucuri", "cdn"),
        ],
    )
    def test_cdn_by_asn(self, asn: int | str, org: str, expected: IpClass) -> None:
        result = classify_ip(org=org, asn=asn)
        assert result == expected

    @pytest.mark.parametrize(
        "org",
        [
            "Cloudflare, Inc.",
            "AKAMAI-ASN1",
            "Fastly - CDN",
            "Incapsula Inc.",
            "StackPath LLC",
            "Sucuri Security",
            "CDN77",
        ],
    )
    def test_cdn_by_org_keyword(self, org: str) -> None:
        result = classify_ip(org=org, asn=99999)
        assert result == "cdn"

    def test_cdn_by_anycast(self) -> None:
        result = classify_ip(org="Unknown Org", asn=99999, anycast=True)
        assert result == "cdn"

    def test_cdn_by_asn_name(self) -> None:
        result = classify_ip(org="", asn=99999, asn_name="CLOUDFLARENET")
        assert result == "cdn"


class TestClassifyIpByCloud:
    """Cloud provider detection via ASN and org name."""

    @pytest.mark.parametrize(
        "asn,org,expected",
        [
            (14061, "DigitalOcean, LLC", "cloud"),
            (24940, "Hetzner Online GmbH", "cloud"),
            (16276, "OVH SAS", "cloud"),
            (20473, "The Constant Company, LLC", "cloud"),
            (8075, "Microsoft Corporation", "cloud"),
        ],
    )
    def test_cloud_by_asn(self, asn: int, org: str, expected: IpClass) -> None:
        result = classify_ip(org=org, asn=asn)
        assert result == expected

    @pytest.mark.parametrize(
        "org",
        [
            "Amazon.com, Inc.",
            "Amazon Web Services",
            "Microsoft Azure",
            "Google Cloud Platform",
            "DigitalOcean",
            "Hetzner Online GmbH",
            "OVH SAS",
            "Vultr Holdings, LLC",
            "Linode, LLC",
            "Contabo GmbH",
        ],
    )
    def test_cloud_by_org_keyword(self, org: str) -> None:
        result = classify_ip(org=org, asn=99999)
        assert result == "cloud"


class TestClassifyIpByDirectHost:
    """Direct-host detection via PTR hostname matching target domain."""

    def test_ptr_matches_target_exactly(self) -> None:
        result = classify_ip(
            org="ctbctelecom.com.br",
            asn=99999,
            hostname="example.com",
            target_domain="example.com",
        )
        assert result == "direct_host"

    def test_ptr_subdomain_of_target(self) -> None:
        result = classify_ip(
            org="Some ISP",
            asn=99999,
            hostname="server1.example.com",
            target_domain="example.com",
        )
        assert result == "direct_host"

    def test_ptr_trailing_dot(self) -> None:
        result = classify_ip(
            org="Some ISP",
            asn=99999,
            hostname="mail.example.com.",
            target_domain="example.com.",
        )
        assert result == "direct_host"

    def test_ptr_no_match(self) -> None:
        result = classify_ip(
            org="Some ISP",
            asn=99999,
            hostname="server.otherdomain.com",
            target_domain="example.com",
        )
        assert result == "isp"


class TestClassifyIpByIsp:
    """Default ISP classification for unknown providers."""

    def test_unknown_asn_and_org(self) -> None:
        result = classify_ip(org="ctbctelecom.com.br", asn=28573)
        assert result == "isp"

    def test_empty_fields(self) -> None:
        result = classify_ip()
        assert result == "isp"

    def test_residential_isp(self) -> None:
        result = classify_ip(org="Claro NXT Telecomunicacoes SA", asn=28573)
        assert result == "isp"

    def test_brazilian_telecom(self) -> None:
        result = classify_ip(org="Vivo S.A.", asn=26599)
        assert result == "isp"


class TestClassifyIpPriority:
    """Classification priority: anycast > CDN ASN > CDN org > direct_host > cloud > ISP."""

    def test_anycast_overrides_cloud_asn(self) -> None:
        result = classify_ip(org="Amazon.com", asn=16509, anycast=True)
        assert result == "cdn"

    def test_cdn_asn_overrides_cloud_org(self) -> None:
        result = classify_ip(org="Amazon.com", asn=13335)
        assert result == "cdn"

    def test_direct_host_overrides_isp(self) -> None:
        result = classify_ip(
            org="Random ISP Co",
            asn=99999,
            hostname="web.example.com",
            target_domain="example.com",
        )
        assert result == "direct_host"

    def test_cdn_overrides_direct_host(self) -> None:
        result = classify_ip(
            org="Cloudflare, Inc.",
            asn=13335,
            hostname="example.com",
            target_domain="example.com",
        )
        assert result == "cdn"


class TestParseAsn:
    """Edge cases for ASN string parsing."""

    def test_as_prefix(self) -> None:
        result = classify_ip(org="Cloudflare, Inc.", asn="AS13335")
        assert result == "cdn"

    def test_integer(self) -> None:
        result = classify_ip(org="Cloudflare, Inc.", asn=13335)
        assert result == "cdn"

    def test_none(self) -> None:
        result = classify_ip(org="Unknown", asn=None)
        assert result == "isp"

    def test_invalid_string(self) -> None:
        result = classify_ip(org="Unknown", asn="notanumber")
        assert result == "isp"
