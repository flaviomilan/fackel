"""Tests for the OSINT specialist registry and per-specialist builder.

Parallel fan-out (dispatch / specialist node / collect) is covered in
``tests/agents/test_parallel_osint.py``.
"""

from __future__ import annotations

import pytest

from fackel.agents.osint import specialists
from fackel.agents.osint.agent import TOOLS
from fackel.agents.osint.agent import build as build_osint
from fackel.agents.osint.specialists import SPECIALISTS, SPECIALISTS_BY_NAME, build_specialist


@pytest.fixture(autouse=True)
def _clear_agent_caches():
    """Compiled agents are lru_cached; clear so per-test tool-gating patches apply."""
    build_osint.cache_clear()
    build_specialist.cache_clear()
    yield
    build_osint.cache_clear()
    build_specialist.cache_clear()


class TestRegistryCoverage:
    def test_every_tool_assigned_to_a_specialist(self) -> None:
        tool_names = {t.name for t in TOOLS}
        assigned: set[str] = set()
        for spec in SPECIALISTS:
            assigned |= set(spec.tool_names)
        assert tool_names <= assigned, f"unassigned tools: {tool_names - assigned}"
        assert assigned <= tool_names, f"unknown tool names: {assigned - tool_names}"

    def test_specialist_tools_resolve_to_objects(self) -> None:
        for spec in SPECIALISTS:
            assert len(spec.tools) == len(spec.tool_names)
            assert all(getattr(t, "name", "") in spec.tool_names for t in spec.tools)

    def test_by_name_lookup(self) -> None:
        assert set(SPECIALISTS_BY_NAME) == {s.name for s in SPECIALISTS}


class TestBuildSpecialist:
    def test_builds_keyless_specialist(self, monkeypatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        dns_infra = SPECIALISTS_BY_NAME["dns_infra"]
        assert build_specialist(dns_infra) is not None

    def test_none_when_no_tools_available(self, monkeypatch) -> None:
        monkeypatch.setattr(specialists, "filter_tools", lambda tools: ([], []))
        monkeypatch.setattr(specialists, "available_binaries", lambda tools: ([], []))
        assert build_specialist(SPECIALISTS[0]) is None
