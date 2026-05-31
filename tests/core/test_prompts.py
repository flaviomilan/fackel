"""Tests for the prompt loader — load_prompt, load_section, compose_prompt."""

from __future__ import annotations

import pytest

from fackel.prompts import compose_prompt, load_prompt, load_section


class TestLoadPrompt:
    """Verify soul + skill composition."""

    def test_returns_string(self):
        result = load_prompt("osint")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_soul_and_skill(self):
        result = load_prompt("osint")
        assert "---" in result  # separator between sections

    def test_all_skills_loadable(self):
        skills = ["osint", "port_scan", "vuln_scan", "triage", "report", "judge"]
        for skill in skills:
            result = load_prompt(skill)
            assert isinstance(result, str)
            assert len(result) > 100, f"Skill {skill} seems too short"

    def test_unknown_skill_raises(self):
        with pytest.raises(FileNotFoundError):
            load_prompt("nonexistent_skill_xyz")


class TestLoadSection:
    """Verify arbitrary section loading."""

    @pytest.mark.parametrize(
        "path",
        [
            "stages/enumeration",
            "stages/correlation",
            "stages/gap_identification",
            "stages/strategic_analysis",
            "stages/evidence_consolidation",
            "stages/final_report",
            "orchestrator/phase_transition",
            "orchestrator/continue_or_stop",
            "orchestrator/surface_exhaustion",
            "orchestrator/loop_detection",
            "orchestrator/pivot_priority",
            "tools/port_scanning",
            "tools/vuln_scanning",
            "tools/api_fuzzing",
            "tools/security_headers",
            "tools/sqli_scanning",
            "tools/jwt_analysis",
            "tools/ssrf_scanning",
            "tools/graphql_scanning",
            "tools/http_probing",
            "tools/web_crawling",
            "tools/wordpress_scanning",
            "tools/xss_scanning",
            "contracts/nmap",
            "contracts/nuclei",
            "contracts/httpx",
            "validation/false_positive_detection",
            "validation/severity_classification",
            "validation/source_reliability",
            "synthesis/evidence_correlation",
            "synthesis/entity_grouping",
            "synthesis/pattern_detection",
            "reporting/technical",
            "reporting/executive",
            "reporting/actionable_summary",
            "reporting/risk_oriented",
            "strategy/approach_change",
            "strategy/depth_adjustment",
            "strategy/error_resilience",
        ],
    )
    def test_loads_section(self, path: str):
        result = load_section(path)
        assert isinstance(result, str)
        assert len(result) > 50, f"Section {path} seems too short"

    def test_unknown_section_raises(self):
        with pytest.raises(FileNotFoundError):
            load_section("nonexistent/section_xyz")


class TestComposePrompt:
    """Verify multi-section prompt composition."""

    def test_no_extras_equals_load_prompt(self):
        base = load_prompt("osint")
        composed = compose_prompt("osint")
        assert composed == base

    def test_single_extra_appended(self):
        base = load_prompt("osint")
        composed = compose_prompt("osint", "tools/http_probing")
        assert composed.startswith(base)
        assert len(composed) > len(base)
        # Extra section should be present
        section = load_section("tools/http_probing")
        assert section in composed

    def test_multiple_extras_appended(self):
        composed = compose_prompt(
            "port_scan",
            "tools/port_scanning",
            "contracts/nmap",
        )
        assert load_section("tools/port_scanning") in composed
        assert load_section("contracts/nmap") in composed

    def test_sections_separated_by_divider(self):
        composed = compose_prompt(
            "judge",
            "orchestrator/phase_transition",
            "orchestrator/continue_or_stop",
        )
        # Count separators: soul-skill, skill-extra1, extra1-extra2 = minimum 3
        assert composed.count("\n\n---\n\n") >= 3

    def test_unknown_extra_raises(self):
        with pytest.raises(FileNotFoundError):
            compose_prompt("osint", "nonexistent/path_xyz")

    def test_triage_composition(self):
        """Verify triage agent's full composition."""
        composed = compose_prompt(
            "triage",
            "validation/false_positive_detection",
            "validation/severity_classification",
            "synthesis/evidence_correlation",
            "stages/gap_identification",
        )
        assert "triage" in composed.lower() or "triagem" in composed.lower()
        assert load_section("validation/false_positive_detection") in composed
        assert load_section("stages/gap_identification") in composed

    def test_report_composition(self):
        """Verify report agent's full composition."""
        composed = compose_prompt(
            "report",
            "reporting/technical",
            "reporting/executive",
            "stages/final_report",
        )
        assert load_section("reporting/technical") in composed
        assert load_section("reporting/executive") in composed
        assert load_section("stages/final_report") in composed

    def test_judge_composition(self):
        """Verify judge/evaluator's full composition."""
        composed = compose_prompt(
            "judge",
            "orchestrator/phase_transition",
            "orchestrator/continue_or_stop",
            "orchestrator/surface_exhaustion",
        )
        assert load_section("orchestrator/phase_transition") in composed
        assert load_section("orchestrator/surface_exhaustion") in composed
