"""Pre-report verification — multi-source corroboration of findings.

Before the report is written, every persisted fact is classified by how well it
is *corroborated*: a fact reported by several independent tools (or a single
highly-trusted source) is **verified**; a fact resting on one low-trust source is
**unverified** and should be presented with a caveat.

This builds on the existing provenance model (:mod:`fackel.confidence`,
``InformationRecord.source_tools`` / ``confidence``) rather than re-deriving trust
— it is fully deterministic (no LLM, no extra traffic to the target) and feeds a
verification section into the report context so claims carry an explicit trust
level, with high-impact single-source findings flagged for manual confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fackel.domain import InformationType
from fackel.persistence.store import InformationStore

# A fact is "verified" when corroborated by at least this many distinct source
# tools, OR carries at least this confidence from a single authoritative source.
MIN_SOURCES = 2
MIN_CONFIDENCE = 0.85

# Finding types where a single, uncorroborated source warrants an explicit flag.
HIGH_IMPACT_TYPES = (
    InformationType.SECURITY_VULNERABILITY,
    InformationType.CREDENTIAL_LEAK,
)


@dataclass
class FlaggedFinding:
    """A high-impact finding that lacks corroboration."""

    type: str
    value: str
    confidence: float
    sources: list[str]


@dataclass
class VerificationSummary:
    """Outcome of corroborating the knowledge graph before reporting."""

    verified: int = 0
    unverified: int = 0
    flagged: list[FlaggedFinding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.verified + self.unverified

    @property
    def verified_ratio(self) -> float:
        return round(self.verified / self.total, 3) if self.total else 0.0


def _is_verified(distinct_sources: int, confidence: float) -> bool:
    return distinct_sources >= MIN_SOURCES or confidence >= MIN_CONFIDENCE


def verify_findings(
    store: InformationStore,
    *,
    min_sources: int = MIN_SOURCES,
    min_confidence: float = MIN_CONFIDENCE,
) -> VerificationSummary:
    """Classify every record by corroboration; flag high-impact single-source facts.

    A record is *verified* when reported by ``>= min_sources`` distinct tools or
    when its confidence is ``>= min_confidence`` (a single authoritative source).
    High-impact unverified findings (vulnerabilities, credential leaks) are
    collected into :attr:`VerificationSummary.flagged` for manual confirmation.
    """
    summary = VerificationSummary()
    for record in store.all_records():
        distinct = len(set(record.source_tools))
        verified = distinct >= min_sources or record.confidence >= min_confidence
        if verified:
            summary.verified += 1
        else:
            summary.unverified += 1
            if record.type in HIGH_IMPACT_TYPES:
                summary.flagged.append(
                    FlaggedFinding(
                        type=record.type.value,
                        value=record.normalized_value,
                        confidence=record.confidence,
                        sources=sorted(set(record.source_tools)),
                    )
                )
    return summary


def build_verification_md(summary: VerificationSummary) -> str:
    """Render a verification section for the report context.

    Empty string when the store held no records (so passive / unit runs are
    unaffected).
    """
    if summary.total == 0:
        return ""

    lines = [
        "## Verification (multi-source corroboration)",
        f"Of {summary.total} discovered facts, {summary.verified} are corroborated "
        f"(>={MIN_SOURCES} independent sources or confidence >={MIN_CONFIDENCE}) and "
        f"{summary.unverified} rest on a single low-trust source "
        f"(verified ratio: {summary.verified_ratio}).",
        "Treat corroborated facts as reliable; present single-source facts with a "
        "caveat and recommend manual confirmation.",
    ]
    if summary.flagged:
        lines.append(
            "\n**High-impact findings needing manual confirmation "
            "(single, low-confidence source):**"
        )
        for f in summary.flagged:
            srcs = ", ".join(f.sources) or "unknown"
            lines.append(f"  - [{f.type}] {f.value} (confidence={f.confidence}, sources={srcs})")
    return "\n".join(lines)
