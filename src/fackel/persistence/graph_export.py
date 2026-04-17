"""Knowledge-graph export and serialisation.

Renders an :class:`InformationStore`'s records + relationship edges into:

- **JSON** — machine-readable nodes/edges for dashboards or downstream tools.
- **Mermaid** — a quick attack-surface diagram pasteable into Markdown.
- **query context** — a compact textual rendering fed to the NL query agent.

Edge endpoints are mapped back to readable record labels; endpoints with no
materialised record are skipped so the output stays clean.
"""

from __future__ import annotations

from typing import Any

from fackel.persistence.store import InformationStore


def _labels(store: InformationStore) -> dict[str, tuple[str, str, float]]:
    """Map record fingerprint -> (type, normalized_value, confidence)."""
    return {
        r.fingerprint: (r.type.value, r.normalized_value, r.confidence) for r in store.all_records()
    }


def to_json(store: InformationStore) -> dict[str, Any]:
    """Serialise the graph as ``{scan_id, nodes, edges}``."""
    labels = _labels(store)
    nodes = [
        {"fingerprint": fp, "type": t, "value": v, "confidence": c}
        for fp, (t, v, c) in labels.items()
    ]
    edges = [
        {
            "source": e.source_fingerprint,
            "target": e.target_fingerprint,
            "type": e.type.value,
        }
        for e in store.all_edges()
        # Keep only edges whose endpoints are materialised nodes.
        if e.source_fingerprint in labels and e.target_fingerprint in labels
    ]
    return {"scan_id": store.scan_id, "nodes": nodes, "edges": edges}


def _mermaid_escape(text: str) -> str:
    return text.replace('"', "'").replace("[", "(").replace("]", ")")


def to_mermaid(store: InformationStore) -> str:
    """Render the graph as a Mermaid ``graph LR`` diagram."""
    labels = _labels(store)
    lines = ["graph LR"]
    for fp, (type_, value, _conf) in labels.items():
        label = _mermaid_escape(f"{type_}: {value}")
        lines.append(f'  {fp}["{label}"]')
    for edge in store.all_edges():
        if edge.source_fingerprint in labels and edge.target_fingerprint in labels:
            lines.append(
                f"  {edge.source_fingerprint} -->|{edge.type.value}| {edge.target_fingerprint}"
            )
    return "\n".join(lines)


def build_query_context(store: InformationStore, *, max_per_type: int = 40) -> str:
    """Render a compact textual graph for the NL query agent.

    Groups records by type (with confidence) and lists relationships using
    readable labels rather than fingerprints.
    """
    labels = _labels(store)
    by_type: dict[str, list[tuple[str, float]]] = {}
    for type_, value, conf in labels.values():
        by_type.setdefault(type_, []).append((value, conf))

    lines = [f"Knowledge graph for scan {store.scan_id}", "", "ENTITIES:"]
    for type_ in sorted(by_type):
        entries = by_type[type_]
        shown = entries[:max_per_type]
        rendered = ", ".join(f"{v} (conf={c})" for v, c in shown)
        overflow = len(entries) - len(shown)
        if overflow > 0:
            rendered += f", … (+{overflow} more)"
        lines.append(f"- {type_} ({len(entries)}): {rendered}")

    edges = [
        (labels[e.source_fingerprint][1], e.type.value, labels[e.target_fingerprint][1])
        for e in store.all_edges()
        if e.source_fingerprint in labels and e.target_fingerprint in labels
    ]
    if edges:
        lines.append("")
        lines.append("RELATIONSHIPS:")
        for src, rel, tgt in edges[:200]:
            lines.append(f"- {src} --{rel}--> {tgt}")

    return "\n".join(lines)
