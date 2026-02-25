"""Tests for orchestrator node helpers and routing logic."""

from __future__ import annotations

from fackel.agents.orchestrator.nodes._helpers import (
    IP_CLASS_HINTS,
    make_finding,
    get_phase_evaluation,
    prepare_scan_targets,
)
from fackel.agents.orchestrator.nodes.report_and_gates import (
    route_after_osint,
    route_after_port_scan,
)


# ── make_finding ──────────────────────────────────────────────────────────


class TestMakeFinding:
    """Verify Finding dict construction."""

    def test_default_severity_is_info(self):
        f = make_finding("osint", "Test", "detail")
        assert f["severity"] == "info"
        assert f["phase"] == "osint"
        assert f["title"] == "Test"
        assert f["detail"] == "detail"

    def test_custom_severity(self):
        f = make_finding("vuln_scan", "CVE", "critical vuln", severity="critical")
        assert f["severity"] == "critical"

    def test_confidence_default(self):
        f = make_finding("osint", "Title", "Detail")
        assert f["confidence"] == 1.0


# ── get_phase_evaluation ─────────────────────────────────────────────────


class TestGetPhaseEvaluation:
    """Verify evaluation lookup from state."""

    def test_finds_evaluation(self):
        state = {
            "phase_evaluations": [
                {"phase": "port_scan", "score": 0.7, "completeness": "partial"},
            ],
            "target": "example.com",
        }
        result = get_phase_evaluation(state, "port_scan")
        assert result is not None
        assert result["score"] == 0.7

    def test_returns_none_when_missing(self):
        state = {"phase_evaluations": [], "target": "example.com"}
        result = get_phase_evaluation(state, "port_scan")
        assert result is None


# ── prepare_scan_targets ──────────────────────────────────────────────────


class TestPrepareScanTargets:
    """Verify target preparation with IPv6 filtering."""

    def test_ipv4_passes_through(self):
        state = {
            "discovered_ips": ["1.2.3.4", "5.6.7.8"],
            "discovered_subdomains": ["sub.example.com"],
            "target": "example.com",
        }
        ips, subs = prepare_scan_targets(state)
        assert ips == ["1.2.3.4", "5.6.7.8"]
        assert subs == ["sub.example.com"]

    def test_ipv6_filtered_out(self):
        state = {
            "discovered_ips": ["1.2.3.4", "2001:db8::1"],
            "discovered_subdomains": [],
            "target": "example.com",
        }
        ips, subs = prepare_scan_targets(state)
        assert ips == ["1.2.3.4"]

    def test_empty_state(self):
        state = {"target": "example.com"}
        ips, subs = prepare_scan_targets(state)
        assert ips == []
        assert subs == []


# ── Routing functions ─────────────────────────────────────────────────────


class TestRouteAfterOsint:
    """Verify routing decisions after OSINT phase."""

    def test_passive_goes_to_report(self):
        state = {"active_scan": False, "target": "example.com"}
        assert route_after_osint(state) == "report"

    def test_active_with_ips_goes_to_approval(self):
        state = {
            "active_scan": True,
            "discovered_ips": ["1.2.3.4"],
            "discovered_subdomains": [],
            "target": "example.com",
        }
        assert route_after_osint(state) == "approval_gate"

    def test_active_with_subdomains_goes_to_approval(self):
        state = {
            "active_scan": True,
            "discovered_ips": [],
            "discovered_subdomains": ["sub.example.com"],
            "target": "example.com",
        }
        assert route_after_osint(state) == "approval_gate"

    def test_active_no_targets_goes_to_report(self):
        state = {
            "active_scan": True,
            "discovered_ips": [],
            "discovered_subdomains": [],
            "target": "example.com",
        }
        assert route_after_osint(state) == "report"

    def test_ipv6_only_goes_to_report(self):
        state = {
            "active_scan": True,
            "discovered_ips": ["2001:db8::1"],
            "discovered_subdomains": [],
            "target": "example.com",
        }
        assert route_after_osint(state) == "report"


class TestRouteAfterPortScan:
    """Verify routing decisions after port scan phase."""

    def test_no_evaluation_proceeds_to_vuln_scan(self):
        state = {"phase_evaluations": [], "target": "example.com"}
        assert route_after_port_scan(state) == "vuln_scan"

    def test_proceed_recommendation(self):
        state = {
            "phase_evaluations": [
                {"phase": "port_scan", "recommendation": "proceed"},
            ],
            "target": "example.com",
        }
        assert route_after_port_scan(state) == "vuln_scan"

    def test_skip_downstream_goes_to_triage(self):
        state = {
            "phase_evaluations": [
                {"phase": "port_scan", "recommendation": "skip_downstream"},
            ],
            "target": "example.com",
        }
        assert route_after_port_scan(state) == "triage"

    def test_adapt_recommendation_proceeds(self):
        state = {
            "phase_evaluations": [
                {"phase": "port_scan", "recommendation": "adapt"},
            ],
            "target": "example.com",
        }
        assert route_after_port_scan(state) == "vuln_scan"
