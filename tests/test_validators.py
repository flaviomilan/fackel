"""Tests for tool input validation — guard_target() and TargetType."""

import pytest

from fackel.tooling import TargetType, guard_target

# ── TargetType.DOMAIN ──────────────────────────────────────────────────


class TestGuardTargetDomain:
    """guard_target with TargetType.DOMAIN."""

    @pytest.mark.parametrize(
        "value",
        [
            "example.com",
            "sub.example.com",
            "deep.nested.example.com",
            "example.co.uk",
        ],
    )
    def test_valid_domains(self, value: str) -> None:
        cleaned, err = guard_target(value, "test_tool", TargetType.DOMAIN)
        assert err is None
        assert cleaned == value

    def test_strips_whitespace(self) -> None:
        cleaned, err = guard_target("  example.com  ", "test_tool", TargetType.DOMAIN)
        assert err is None
        assert cleaned == "example.com"

    def test_rejects_ip_address(self) -> None:
        _, err = guard_target("192.168.1.1", "test_tool", TargetType.DOMAIN)
        assert err is not None
        assert err["status"] == "error"

    def test_rejects_empty(self) -> None:
        _, err = guard_target("", "test_tool", TargetType.DOMAIN)
        assert err is not None
        assert "empty" in err["error"]

    def test_rejects_whitespace_only(self) -> None:
        _, err = guard_target("   ", "test_tool", TargetType.DOMAIN)
        assert err is not None

    @pytest.mark.parametrize(
        "value",
        [
            "example.com; rm -rf /",
            "example.com | cat /etc/passwd",
            "example.com`whoami`",
            "$(evil)",
            "test&bg",
        ],
    )
    def test_rejects_shell_metacharacters(self, value: str) -> None:
        _, err = guard_target(value, "test_tool", TargetType.DOMAIN)
        assert err is not None
        assert err["status"] == "error"


# ── TargetType.IP ──────────────────────────────────────────────────────


class TestGuardTargetIP:
    """guard_target with TargetType.IP."""

    @pytest.mark.parametrize(
        "value",
        [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
            "::1",
            "2606:4700::6811:d209",
        ],
    )
    def test_valid_ips(self, value: str) -> None:
        cleaned, err = guard_target(value, "test_tool", TargetType.IP)
        assert err is None
        assert cleaned == value

    def test_rejects_domain(self) -> None:
        _, err = guard_target("example.com", "test_tool", TargetType.IP)
        assert err is not None
        assert err["status"] == "error"


# ── TargetType.HOST ────────────────────────────────────────────────────


class TestGuardTargetHost:
    """guard_target with TargetType.HOST — domain or IP."""

    def test_accepts_domain(self) -> None:
        cleaned, err = guard_target("example.com", "test_tool", TargetType.HOST)
        assert err is None
        assert cleaned == "example.com"

    def test_accepts_ip(self) -> None:
        cleaned, err = guard_target("10.0.0.1", "test_tool", TargetType.HOST)
        assert err is None
        assert cleaned == "10.0.0.1"

    def test_rejects_garbage(self) -> None:
        _, err = guard_target("not a valid host!!!", "test_tool", TargetType.HOST)
        assert err is not None


# ── TargetType.URL ─────────────────────────────────────────────────────


class TestGuardTargetURL:
    """guard_target with TargetType.URL."""

    @pytest.mark.parametrize(
        "value",
        [
            "http://example.com",
            "https://example.com/path?q=1",
            "https://sub.example.com:8443/api",
        ],
    )
    def test_valid_urls(self, value: str) -> None:
        cleaned, err = guard_target(value, "test_tool", TargetType.URL)
        assert err is None
        assert cleaned == value

    def test_rejects_bare_domain(self) -> None:
        _, err = guard_target("example.com", "test_tool", TargetType.URL)
        assert err is not None
        assert "http" in err["error"].lower()


# ── TargetType.HOST_OR_URL ─────────────────────────────────────────────


class TestGuardTargetHostOrURL:
    """guard_target with TargetType.HOST_OR_URL."""

    def test_accepts_url(self) -> None:
        cleaned, err = guard_target("https://example.com", "test_tool", TargetType.HOST_OR_URL)
        assert err is None
        assert cleaned == "https://example.com"

    def test_accepts_domain(self) -> None:
        cleaned, err = guard_target("example.com", "test_tool", TargetType.HOST_OR_URL)
        assert err is None
        assert cleaned == "example.com"

    def test_accepts_ip(self) -> None:
        cleaned, err = guard_target("10.0.0.1", "test_tool", TargetType.HOST_OR_URL)
        assert err is None
        assert cleaned == "10.0.0.1"
