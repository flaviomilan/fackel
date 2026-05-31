"""Stable fingerprint derivation for InformationRecord deduplication."""

from __future__ import annotations

import hashlib

from .types import InformationType

_DIGEST_LEN = 16


def fingerprint(info_type: InformationType, normalized_value: str) -> str:
    """Return a stable 16-char hex fingerprint for ``(type, value)``.

    Identity is built only from the semantic type and the normalized
    value — never from tool, execution, or run metadata.  This is what
    allows different tools to converge onto the same
    :class:`InformationRecord` and what powers append-only timeline
    tracking across runs.
    """
    if not normalized_value or not normalized_value.strip():
        raise ValueError("normalized_value must be non-empty")
    payload = f"{info_type.value}|{normalized_value}".encode()
    return hashlib.sha256(payload).hexdigest()[:_DIGEST_LEN]


def edge_fingerprint(source_fp: str, rel_type: str, target_fp: str) -> str:
    """Return a stable fingerprint for a directed edge.

    Identity is the ``(source, relationship-type, target)`` triple, so the
    same relationship discovered by different tools converges onto one edge
    in the knowledge graph (mirrors :func:`fingerprint` for records).
    """
    payload = f"{source_fp}|{rel_type}|{target_fp}".encode()
    return hashlib.sha256(payload).hexdigest()[:_DIGEST_LEN]
