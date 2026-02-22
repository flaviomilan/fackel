"""ScanState — minimal shared context for the orchestrator graph."""

from __future__ import annotations

from operator import add
from typing import Annotated

from typing_extensions import TypedDict


class ScanState(TypedDict):
    target: str
    """Original target (domain or IP) provided by the user."""

    active_scan: bool
    """Whether active scanning phases are permitted."""

    discovered_ips: list[str]
    """IP addresses discovered during OSINT (fed into port_scan)."""

    findings: Annotated[list[str], add]
    """Agent summaries accumulated across phases (append-only reducer)."""

    unassessed_areas: Annotated[list[dict], add]
    """Technologies/opportunities detected but not covered by any specialist."""

    report: str
    """Final rendered Markdown report."""
