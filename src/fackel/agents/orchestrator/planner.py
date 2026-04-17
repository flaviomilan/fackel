"""Entity-driven pivot planner — the agentic investigation engine.

After an OSINT pass, the planner inspects the knowledge graph (the bound
:class:`~fackel.persistence.store.InformationStore`) for high-value entities
that have **not yet been expanded**, and proposes focused follow-up actions
("pivots").  This turns the fixed pipeline into a self-expanding investigation:
discovering an organisation or an email leads to targeted recon on it, rather
than ending the phase.

Each rule is grounded in the graph + the set of tools already executed, so the
loop terminates naturally once the high-value entities have been expanded.
"""

from __future__ import annotations

from dataclasses import dataclass

from fackel.domain import InformationType
from fackel.persistence.store import InformationStore

_MAX_ENTITIES = 20


@dataclass(frozen=True)
class PivotDirective:
    """A focused follow-up the agent should perform on discovered entities."""

    kind: str
    instruction: str
    entities: list[str]


def plan_osint_pivots(store: InformationStore) -> list[PivotDirective]:
    """Return pivot directives for unexpanded high-value entities.

    Rules are intentionally conservative and execution-aware: a directive is
    only emitted while the expanding tool has *not* run, so each pivot fires at
    most once and the loop self-terminates.
    """
    directives: list[PivotDirective] = []
    executed = store.tools_executed()

    # Emails were discovered (e.g. via hunter_email_search) but never checked
    # for breach exposure.
    emails = sorted({r.normalized_value for r in store.records_by_type(InformationType.EMAIL)})
    if emails and "analyze_email" not in executed:
        directives.append(
            PivotDirective(
                kind="analyze_emails",
                instruction=(
                    "These email addresses were discovered but not yet checked for "
                    "breach exposure. Call analyze_email on each."
                ),
                entities=emails[:_MAX_ENTITIES],
            )
        )

    # An organisation was identified but its public code surface was not searched.
    orgs = sorted({r.original_value for r in store.records_by_type(InformationType.ORGANIZATION)})
    if orgs and "github_repo_discovery" not in executed:
        directives.append(
            PivotDirective(
                kind="expand_org",
                instruction=(
                    "An organisation was identified but its public code was not "
                    "searched. Run github_repo_discovery for it, then trufflehog_scan "
                    "on any repositories found."
                ),
                entities=orgs[:_MAX_ENTITIES],
            )
        )

    return directives


def build_pivot_prompt(target: str, directives: list[PivotDirective]) -> str:
    """Build a focused re-invocation prompt for the OSINT agent."""
    lines = [
        f"PIVOT — expand the investigation of {target} based on what was just discovered.",
        "Perform only the specific follow-ups below. Do NOT repeat earlier tool calls.",
        "",
    ]
    for directive in directives:
        entities = ", ".join(directive.entities) if directive.entities else "(see prior findings)"
        lines.append(f"- {directive.instruction}")
        lines.append(f"  Entities: {entities}")
    lines.append("")
    lines.append("When done, summarise only the NEW findings from these follow-ups.")
    return "\n".join(lines)
