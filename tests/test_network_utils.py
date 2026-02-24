"""Tests for network utilities — is_valid_ip, is_valid_domain, sanitize_target."""

import pytest

from fackel.tooling import is_valid_domain, is_valid_ip, is_reverse_ptr_subdomain, sanitize_target


class TestIsValidIP:
    """IPv4 and IPv6 address validation."""

    @pytest.mark.parametrize("value", [
        "192.168.1.1", "10.0.0.1", "127.0.0.1", "255.255.255.255",
        "::1", "2606:4700:3034::6815:24fa",
    ])
    def test_valid(self, value: str) -> None:
        assert is_valid_ip(value) is True

    @pytest.mark.parametrize("value", [
        "not-an-ip", "example.com", "999.999.999.999", "", "  ",
    ])
    def test_invalid(self, value: str) -> None:
        assert is_valid_ip(value) is False


class TestIsValidDomain:
    """Domain name validation."""

    @pytest.mark.parametrize("value", [
        "example.com", "sub.example.com", "example.co.uk",
    ])
    def test_valid(self, value: str) -> None:
        assert is_valid_domain(value) is True

    @pytest.mark.parametrize("value", [
        "192.168.1.1", "", "not valid!", "-invalid.com",
    ])
    def test_invalid(self, value: str) -> None:
        assert is_valid_domain(value) is False


class TestIsReversePtrSubdomain:
    """Reverse-PTR style subdomain detection."""

    @pytest.mark.parametrize("value", [
        "200-210-75-128.example.com",
        "10-0-0-1.static.provider.com",
    ])
    def test_detected(self, value: str) -> None:
        assert is_reverse_ptr_subdomain(value) is True

    @pytest.mark.parametrize("value", [
        "www.example.com", "api.example.com", "mail.example.com",
    ])
    def test_not_detected(self, value: str) -> None:
        assert is_reverse_ptr_subdomain(value) is False


class TestSanitizeTarget:
    """Target string sanitization."""

    def test_strips_whitespace(self) -> None:
        assert sanitize_target("  example.com  ") == "example.com"

    def test_preserves_valid_domain(self) -> None:
        result = sanitize_target("EXAMPLE.COM")
        assert result == "EXAMPLE.COM"
