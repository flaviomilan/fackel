"""Report reviewer / QA — the "revisado" pass.

Takes the draft report and the knowledge graph and:

1. Builds a **must-cover manifest** of high-value findings (every vulnerability
   and credential leak, plus high-confidence assets) from the structured store.
2. **Deterministically** detects which of those are missing from the draft.
3. Asks an LLM editor to incorporate the missing ones and fix accuracy/severity
   (anti-hallucination: nothing outside the structured data).
4. Appends a **computed** coverage footer (not LLM-fabricated) so the report
   honestly states how complete it is.

The deterministic steps mean QA never silently trusts the LLM.
"""

from __future__ import annotations

import logging

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from fackel.agents.config import build_llm
from fackel.domain import InformationType
from fackel.persistence.store import InformationStore

logger = logging.getLogger(__name__)

_HIGH_CONFIDENCE = 0.8
# Findings that must always be represented in the report.
_CRITICAL_TYPES = (InformationType.SECURITY_VULNERABILITY, InformationType.CREDENTIAL_LEAK)
# Assets that must be represented when high-confidence.
_HIGH_VALUE_ASSET_TYPES = (
    InformationType.SUBDOMAIN,
    InformationType.IP_ADDRESS,
    InformationType.OPEN_PORT,
    InformationType.EMAIL,
    InformationType.ORGANIZATION,
)

_REVIEW_SYSTEM = (
    "You are a senior reviewer/editor performing QA on a draft penetration-test "
    "report. You receive the draft plus a list of high-value findings (from "
    "structured tool data) that MUST appear in the report.\n\n"
    "Your job:\n"
    "- Ensure every must-cover finding is represented, in the right section and "
    "with appropriate severity; weave in any that are missing.\n"
    "- Remove or correct any claim NOT supported by the structured findings "
    "(no hallucinations).\n"
    "- Fix severity and consistency issues; keep the professional structure.\n\n"
    "Return the COMPLETE corrected report in Markdown. Do NOT add a coverage/QA "
    "footer — that is appended automatically."
)


def _must_cover(store: InformationStore) -> list[tuple[str, str]]:
    """Return ``(type, value)`` high-value findings the report must contain."""
    items: list[tuple[str, str]] = []
    for info_type in _CRITICAL_TYPES:
        items += [(info_type.value, r.normalized_value) for r in store.records_by_type(info_type)]
    for info_type in _HIGH_VALUE_ASSET_TYPES:
        items += [
            (info_type.value, r.normalized_value)
            for r in store.records_by_type(info_type)
            if r.confidence >= _HIGH_CONFIDENCE
        ]
    return items


def _gaps(report: str, must: list[tuple[str, str]]) -> list[tuple[str, str]]:
    low = report.lower()
    return [(t, v) for (t, v) in must if v.lower() not in low]


def _coverage_footer(
    must: list[tuple[str, str]],
    draft_gaps: list[tuple[str, str]],
    final_gaps: list[tuple[str, str]],
) -> str:
    total = len(must)
    present = total - len(final_gaps)
    pct = 100 if total == 0 else round(present * 100 / total)
    lines = [
        "",
        "---",
        "",
        "## Review & Coverage",
        "",
        f"- {present}/{total} high-value findings represented in the final report ({pct}%).",
    ]
    if draft_gaps:
        incorporated = max(len(draft_gaps) - len(final_gaps), 0)
        lines.append(
            f"- Reviewer incorporated {incorporated} of {len(draft_gaps)} "
            "finding(s) missing from the draft."
        )
    else:
        lines.append("- All high-value findings were already present in the draft.")
    if final_gaps:
        missing = ", ".join(v for _, v in final_gaps[:20])
        if len(final_gaps) > 20:
            missing += " …"
        lines.append(f"- ⚠ Still not represented: {missing}.")
    return "\n".join(lines)


def review_report(
    draft: str,
    store: InformationStore,
    *,
    model_name: str | None = None,
    config: RunnableConfig | None = None,
) -> str:
    """Return the reviewed report (polished + computed coverage footer).

    No-op (returns *draft*) when there are no high-value findings to verify.
    On LLM failure the draft is kept — QA never drops the report.
    """
    must = _must_cover(store)
    if not must:
        return draft

    draft_gaps = _gaps(draft, must)
    final = draft
    try:
        llm = build_llm("review", model_name=model_name, temperature=0)
        must_txt = "\n".join(f"- [{t}] {v}" for t, v in must)
        gaps_txt = "\n".join(f"- [{t}] {v}" for t, v in draft_gaps) or "(none — all present)"
        human = (
            f"DRAFT REPORT:\n\n{draft}\n\n"
            f"MUST-COVER high-value findings (from structured data):\n{must_txt}\n\n"
            f"MISSING FROM THE DRAFT — incorporate these:\n{gaps_txt}"
        )
        response = llm.invoke(
            [SystemMessage(content=_REVIEW_SYSTEM), HumanMessage(content=human)],
            config=config,
        )
        final = response.content if isinstance(response.content, str) else str(response.content)
    except Exception:
        logger.exception("review_report: LLM review failed — keeping the draft")
        final = draft

    final_gaps = _gaps(final, must)
    return final + "\n" + _coverage_footer(must, draft_gaps, final_gaps)
