"""Tests for tool input validation — guard_target() and TargetType."""

import pytest
from langchain_core.tools import ToolException

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
        assert guard_target(value, "test_tool", TargetType.DOMAIN) == value

    def test_strips_whitespace(self) -> None:
        assert guard_target("  example.com  ", "test_tool", TargetType.DOMAIN) == "example.com"

    def test_rejects_ip_address(self) -> None:
        with pytest.raises(ToolException):
            guard_target("192.168.1.1", "test_tool", TargetType.DOMAIN)

    def test_rejects_empty(self) -> None:
        with pytest.raises(ToolException, match="empty"):
            guard_target("", "test_tool", TargetType.DOMAIN)

    def test_rejects_whitespace_only(self) -> None:
        with pytest.raises(ToolException):
            guard_target("   ", "test_tool", TargetType.DOMAIN)

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
        with pytest.raises(ToolException):
            guard_target(value, "test_tool", TargetType.DOMAIN)


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
        assert guard_target(value, "test_tool", TargetType.IP) == value

    def test_rejects_domain(self) -> None:
        with pytest.raises(ToolException):
            guard_target("example.com", "test_tool", TargetType.IP)


# ── TargetType.HOST ────────────────────────────────────────────────────


class TestGuardTargetHost:
    """guard_target with TargetType.HOST — domain or IP."""

    def test_accepts_domain(self) -> None:
        assert guard_target("example.com", "test_tool", TargetType.HOST) == "example.com"

    def test_accepts_ip(self) -> None:
        assert guard_target("10.0.0.1", "test_tool", TargetType.HOST) == "10.0.0.1"

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ToolException):
            guard_target("not a valid host!!!", "test_tool", TargetType.HOST)


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
        assert guard_target(value, "test_tool", TargetType.URL) == value

    def test_rejects_bare_domain(self) -> None:
        with pytest.raises(ToolException, match=r"(?i)http"):
            guard_target("example.com", "test_tool", TargetType.URL)


# ── TargetType.HOST_OR_URL ─────────────────────────────────────────────


class TestGuardTargetHostOrURL:
    """guard_target with TargetType.HOST_OR_URL."""

    def test_accepts_url(self) -> None:
        assert (
            guard_target("https://example.com", "test_tool", TargetType.HOST_OR_URL)
            == "https://example.com"
        )

    def test_accepts_domain(self) -> None:
        assert guard_target("example.com", "test_tool", TargetType.HOST_OR_URL) == "example.com"

    def test_accepts_ip(self) -> None:
        assert guard_target("10.0.0.1", "test_tool", TargetType.HOST_OR_URL) == "10.0.0.1"
