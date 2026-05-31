"""Tests for Rules-of-Engagement scope enforcement."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from langchain_core.tools import ToolException

from fackel.scope import check_scope, clear_scope_cache
from fackel.settings import _reset_settings
from fackel.tooling.validators import TargetType, guard_target


def _reset() -> None:
    _reset_settings()
    clear_scope_cache()


@pytest.fixture()
def write_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], Path]]:
    """Write a scope TOML file, point the env at it, and reset caches."""

    def _write(content: str) -> Path:
        p = tmp_path / "scope.toml"
        p.write_text(content, encoding="utf-8")
        monkeypatch.setenv("FACKEL_SCOPE_FILE", str(p))
        _reset()
        return p

    yield _write
    _reset()


@pytest.fixture()
def no_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point the scope env at a non-existent file (permissive default)."""
    monkeypatch.setenv("FACKEL_SCOPE_FILE", str(tmp_path / "absent.toml"))
    _reset()
    yield
    _reset()


class TestCheckScope:
    def test_no_file_is_permissive(self, no_scope: None) -> None:
        assert check_scope("anything.example.com").allowed is True

    def test_in_scope_allowlist_allows_match(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\n')
        assert check_scope("example.com").allowed is True

    def test_in_scope_apex_covers_subdomains(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\n')
        assert check_scope("api.example.com").allowed is True

    def test_in_scope_rejects_non_match(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\n')
        d = check_scope("evil.test")
        assert d.allowed is False
        assert d.reason and "allowlist" in d.reason

    def test_lookalike_domain_not_matched(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\n')
        assert check_scope("notexample.com").allowed is False

    def test_out_of_scope_denylist_wins(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\nout_of_scope = ["admin.example.com"]\n')
        d = check_scope("admin.example.com")
        assert d.allowed is False
        assert d.reason and "out of scope" in d.reason

    def test_empty_in_scope_is_permissive_except_denylist(
        self, write_scope: Callable[[str], Path]
    ) -> None:
        write_scope('out_of_scope = ["10.0.0.0/8"]\n')
        assert check_scope("example.com").allowed is True
        assert check_scope("10.1.2.3").allowed is False

    def test_wildcard_domain(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["*.corp.example.com"]\n')
        assert check_scope("a.corp.example.com").allowed is True
        assert check_scope("corp.example.com").allowed is True
        assert check_scope("example.com").allowed is False

    def test_cidr_membership(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["203.0.113.0/24"]\n')
        assert check_scope("203.0.113.10").allowed is True
        assert check_scope("203.0.114.10").allowed is False

    def test_malformed_toml_is_treated_as_no_scope(
        self, write_scope: Callable[[str], Path]
    ) -> None:
        write_scope("in_scope = [unclosed\n")
        assert check_scope("anything.test").allowed is True


class TestGuardTargetIntegration:
    def test_in_scope_target_passes(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\n')
        assert guard_target("api.example.com", "t", TargetType.DOMAIN) == "api.example.com"

    def test_out_of_scope_domain_raises(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["example.com"]\n')
        with pytest.raises(ToolException):
            guard_target("evil.example.org", "t", TargetType.DOMAIN)

    def test_out_of_scope_ip_raises(self, write_scope: Callable[[str], Path]) -> None:
        write_scope('in_scope = ["203.0.113.0/24"]\n')
        with pytest.raises(ToolException):
            guard_target("198.51.100.7", "t", TargetType.IP)

    def test_no_scope_does_not_change_behaviour(self, no_scope: None) -> None:
        assert guard_target("example.com", "t", TargetType.DOMAIN) == "example.com"
