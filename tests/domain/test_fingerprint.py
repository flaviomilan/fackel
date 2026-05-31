"""Fingerprint stability and validation tests."""

from __future__ import annotations

import pytest

from fackel.domain import InformationType, fingerprint


def test_fingerprint_is_stable_for_same_inputs() -> None:
    a = fingerprint(InformationType.DOMAIN, "example.com")
    b = fingerprint(InformationType.DOMAIN, "example.com")
    assert a == b
    assert len(a) == 16


def test_fingerprint_differs_for_different_types() -> None:
    a = fingerprint(InformationType.DOMAIN, "example.com")
    b = fingerprint(InformationType.SUBDOMAIN, "example.com")
    assert a != b


def test_fingerprint_differs_for_different_values() -> None:
    a = fingerprint(InformationType.DOMAIN, "example.com")
    b = fingerprint(InformationType.DOMAIN, "example.org")
    assert a != b


def test_fingerprint_rejects_empty_value() -> None:
    with pytest.raises(ValueError):
        fingerprint(InformationType.DOMAIN, "")


def test_fingerprint_rejects_whitespace_only_value() -> None:
    with pytest.raises(ValueError):
        fingerprint(InformationType.DOMAIN, "   ")
