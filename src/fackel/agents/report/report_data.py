"""Structured report data derived from the knowledge graph.

The report must reflect **everything** the tools discovered, not a lossy LLM
summary.  All tool output is already persisted as deduplicated, typed,
confidence-scored records (+ relationships) in the :class:`InformationStore`,
so reporting reads *from the store*:

- :func:`build_report_context` — a compact, grounded context fed to the report
  LLM so its prose is anchored in the real data (with confidence + sources).
- :func:`build_asset_inventory_md` — a **deterministic** Markdown inventory of
  every record (no LLM in the loop) appended to the archival report. This is
  the zero-loss completeness guarantee.
"""

from __future__ import annotations

from datetime import datetime

from fackel.domain import InformationType
from fackel.persistence.store import InformationStore

# Report sections, in order, mapped to the entity types they cover.
_SECTIONS: list[tuple[str, list[InformationType]]] = [
    (
        "Infrastructure & Assets",
        [
            InformationType.DOMAIN,
            InformationType.SUBDOMAIN,
            InformationType.IP_ADDRESS,
            InformationType.HISTORICAL_IP_ADDRESS,
            InformationType.TLS_SAN_DOMAIN,
            InformationType.IP_CLASSIFICATION,
        ],
    ),
    (
        "Services & Technology",
        [
            InformationType.OPEN_PORT,
            InformationType.SERVICE_VERSION,
            InformationType.TECH_FINGERPRINT,
        ],
    ),
    (
        "Exposure & Secrets",
        [InformationType.SECURITY_VULNERABILITY, InformationType.CREDENTIAL_LEAK],
    ),
    (
        "People & Organisation",
        [
            InformationType.EMAIL,
            InformationType.PERSON,
            InformationType.USERNAME,
            InformationType.ORGANIZATION,
            InformationType.SOCIAL_ACCOUNT,
            InformationType.PHONE,
            InformationType.DOCUMENT,
        ],
    ),
]


def _fp_value(store: InformationStore) -> dict[str, str]:
    return {r.fingerprint: r.normalized_value for r in store.all_records()}


def build_report_context(store: InformationStore, *, max_per_type: int = 60) -> str:
    """Return a compact, grounded context for the report LLM.

    Groups records by report section with confidence + source tools, then key
    relationships.  Returns ``""`` when the store holds nothing.
    """
    lines: list[str] = [
        "DISCOVERED DATA (structured, authoritative — extracted from tool outputs).",
        "Ground every claim in this data; cite confidence; never omit critical or "
        "high-confidence findings.",
    ]
    any_data = False
    for section, types in _SECTIONS:
        section_lines: list[str] = []
        for info_type in types:
            records = store.records_by_type(info_type)
            if not records:
                continue
            any_data = True
            shown = records[:max_per_type]
            for record in shown:
                sources = ", ".join(record.source_tools) or "unknown"
                section_lines.append(
                    f"  - {record.normalized_value} "
                    f"(confidence={record.confidence}, sources={sources})"
                )
            overflow = len(records) - len(shown)
            if overflow > 0:
                section_lines.append(f"  - … (+{overflow} more {info_type.value})")
        if section_lines:
            lines.append(f"\n## {section}")
            lines.extend(section_lines)

    if not any_data:
        return ""

    values = _fp_value(store)
    rels = [
        (values[e.source_fingerprint], e.type.value, values[e.target_fingerprint])
        for e in store.all_edges()
        if e.source_fingerprint in values and e.target_fingerprint in values
    ]
    if rels:
        lines.append("\n## Relationships")
        for src, rel, tgt in rels[:200]:
            lines.append(f"  - {src} --{rel}--> {tgt}")

    return "\n".join(lines)


def _fmt_dt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M")


def build_asset_inventory_md(store: InformationStore) -> str:
    """Return a deterministic Markdown inventory of *every* record + relationship.

    No LLM — this guarantees the archival report contains all discovered data.
    Returns ``""`` when the store is empty.
    """
    records = store.all_records()
    if not records:
        return ""

    out: list[str] = ["## Complete Asset Inventory", ""]
    out.append(f"_Authoritative, machine-derived inventory — {len(records)} record(s)._\n")

    for _section, types in _SECTIONS:
        for info_type in types:
            by_type = store.records_by_type(info_type)
            if not by_type:
                continue
            out.append(f"### {info_type.value} ({len(by_type)})")
            out.append("| Value | Confidence | Sources | First seen | Last seen |")
            out.append("|-------|-----------|---------|-----------|-----------|")
            for record in by_type:
                sources = ", ".join(record.source_tools) or "—"
                out.append(
                    f"| `{record.normalized_value}` | {record.confidence} | {sources} "
                    f"| {_fmt_dt(record.first_seen_at)} | {_fmt_dt(record.last_seen_at)} |"
                )
            out.append("")

    values = _fp_value(store)
    rels = [
        (values[e.source_fingerprint], e.type.value, values[e.target_fingerprint])
        for e in store.all_edges()
        if e.source_fingerprint in values and e.target_fingerprint in values
    ]
    if rels:
        out.append(f"### Relationships ({len(rels)})")
        out.append("| Source | Relationship | Target |")
        out.append("|--------|--------------|--------|")
        for src, rel, tgt in rels:
            out.append(f"| `{src}` | {rel} | `{tgt}` |")
        out.append("")

    return "\n".join(out)
