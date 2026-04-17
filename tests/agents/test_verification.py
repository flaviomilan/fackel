"""Tests for pre-report multi-source corroboration (verification)."""

from __future__ import annotations

from pathlib import Path

from fackel.agents.report.verification import (
    build_verification_md,
    verify_findings,
)
from fackel.domain import InformationCandidate, InformationType
from fackel.persistence.store import InformationStore


def _cand(
    tool: str,
    value: str,
    info_type: InformationType = InformationType.SUBDOMAIN,
    exec_id: str = "e",
) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        source_execution_id=exec_id,
        source_tool=tool,
        phase="osint",
    )


class TestVerifyFindings:
    def test_multi_source_fact_is_verified(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        # Two distinct low-trust sources → corroborated by count.
        store.ingest([_cand("dnsdumpster_lookup", "a.example.com")], phase="osint")
        store.ingest([_cand("gau_urls", "a.example.com", exec_id="e2")], phase="osint")

        summary = verify_findings(store)
        assert summary.verified == 1
        assert summary.unverified == 0
        assert summary.flagged == []

    def test_single_high_trust_source_is_verified(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        # One authoritative source (dns_resolve trust 0.95 >= MIN_CONFIDENCE).
        store.ingest(
            [_cand("dns_resolve", "b.example.com", InformationType.IP_ADDRESS)],
            phase="osint",
        )
        summary = verify_findings(store)
        assert summary.verified == 1
        assert summary.unverified == 0

    def test_single_low_trust_source_is_unverified(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([_cand("gau_urls", "c.example.com")], phase="osint")
        summary = verify_findings(store)
        assert summary.unverified == 1
        assert summary.verified == 0

    def test_high_impact_single_source_is_flagged(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest(
            [_cand("gau_urls", "CVE-2021-1234 on host", InformationType.SECURITY_VULNERABILITY)],
            phase="vuln_scan",
        )
        summary = verify_findings(store)
        assert len(summary.flagged) == 1
        flag = summary.flagged[0]
        assert flag.type == InformationType.SECURITY_VULNERABILITY.value
        assert "gau_urls" in flag.sources

    def test_verified_ratio(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([_cand("dns_resolve", "v.example.com", InformationType.IP_ADDRESS)], phase="o")
        store.ingest([_cand("gau_urls", "u.example.com")], phase="o")
        summary = verify_findings(store)
        assert summary.total == 2
        assert summary.verified_ratio == 0.5


class TestBuildVerificationMd:
    def test_empty_store_yields_empty_string(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        assert build_verification_md(verify_findings(store)) == ""

    def test_renders_section_and_flags(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest(
            [_cand("gau_urls", "leaked-key", InformationType.CREDENTIAL_LEAK)],
            phase="vuln_scan",
        )
        md = build_verification_md(verify_findings(store))
        assert "## Verification" in md
        assert "manual confirmation" in md
        assert "leaked-key" in md
