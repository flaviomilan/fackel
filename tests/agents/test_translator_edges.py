"""Tests for knowledge-graph edge extraction in the translators."""

from __future__ import annotations

import json

from langchain_core.messages import ToolMessage

from fackel.agents.orchestrator.translators import (
    translate_phase_edges,
    translate_phase_messages,
)
from fackel.domain import InformationType, RelationshipType, fingerprint


def _msg(name: str, data: dict) -> ToolMessage:
    return ToolMessage(
        content=json.dumps({"tool": name, "status": "ok", "data": data}),
        name=name,
        tool_call_id="t",
    )


def _edges_for(messages: list[ToolMessage], target: str):
    _execs, cands = translate_phase_messages(messages, phase="osint", scan_id="t", target=target)
    return translate_phase_edges(messages, cands, phase="osint", target=target)


class TestOsintEdges:
    def test_subdomain_of_and_resolves_to(self) -> None:
        messages = [
            _msg("dns_resolve", {"target": "example.com", "ips": ["1.2.3.4"], "type": "domain"}),
            _msg(
                "dnsdumpster_lookup",
                {
                    "hosts": [
                        {"hostname": "www.example.com", "ip": "1.2.3.4"},
                        {"hostname": "api.example.com", "ip": "5.6.7.8"},
                    ]
                },
            ),
        ]
        edges = _edges_for(messages, "example.com")
        triples = {(e.source_fingerprint, e.type, e.target_fingerprint) for e in edges}

        dom = fingerprint(InformationType.DOMAIN, "example.com")
        www = fingerprint(InformationType.SUBDOMAIN, "www.example.com")
        api = fingerprint(InformationType.SUBDOMAIN, "api.example.com")
        ip1 = fingerprint(InformationType.IP_ADDRESS, "1.2.3.4")
        ip2 = fingerprint(InformationType.IP_ADDRESS, "5.6.7.8")

        # subdomain_of edges
        assert (www, RelationshipType.SUBDOMAIN_OF, dom) in triples
        assert (api, RelationshipType.SUBDOMAIN_OF, dom) in triples
        # resolves_to edges
        assert (dom, RelationshipType.RESOLVES_TO, ip1) in triples
        assert (www, RelationshipType.RESOLVES_TO, ip1) in triples
        assert (api, RelationshipType.RESOLVES_TO, ip2) in triples

    def test_out_of_scope_host_skipped(self) -> None:
        messages = [
            _msg(
                "dnsdumpster_lookup", {"hosts": [{"hostname": "evil.other.com", "ip": "9.9.9.9"}]}
            ),
        ]
        edges = _edges_for(messages, "example.com")
        # the out-of-scope hostname has no in-scope record fingerprint → no edge
        assert all(e.type != RelationshipType.SUBDOMAIN_OF for e in edges)
        assert edges == []

    def test_ip_target_emits_no_resolves(self) -> None:
        messages = [
            _msg("dns_resolve", {"target": "1.2.3.4", "ips": ["1.2.3.4"], "type": "ip"}),
        ]
        edges = _edges_for(messages, "1.2.3.4")
        assert edges == []

    def test_non_osint_phase_returns_empty(self) -> None:
        messages = [_msg("nmap_scan", {"hosts": [{"hostname": "x", "ip": "1.2.3.4"}]})]
        _execs, cands = translate_phase_messages(
            messages, phase="port_scan", scan_id="t", target="example.com"
        )
        assert translate_phase_edges(messages, cands, phase="port_scan", target="example.com") == []


class TestPeopleEntities:
    def test_hunter_emits_email_person_org_and_edges(self) -> None:
        messages = [
            _msg(
                "hunter_email_search",
                {
                    "domain": "example.com",
                    "organization": "Example Inc",
                    "emails": [
                        {
                            "email": "ann@example.com",
                            "first_name": "Ann",
                            "last_name": "Lee",
                            "position": "CTO",
                        }
                    ],
                },
            )
        ]
        _execs, cands = translate_phase_messages(
            messages, phase="osint", scan_id="t", target="example.com"
        )
        types = {c.type for c in cands}
        assert InformationType.EMAIL in types
        assert InformationType.PERSON in types
        assert InformationType.ORGANIZATION in types

        edges = translate_phase_edges(messages, cands, phase="osint", target="example.com")
        etypes = {e.type for e in edges}
        assert RelationshipType.HAS_EMAIL in etypes
        assert RelationshipType.OWNED_BY in etypes
        assert RelationshipType.EMPLOYS in etypes

    def test_analyze_email_emits_credential_leaks(self) -> None:
        messages = [
            _msg(
                "analyze_email",
                {
                    "email": "ann@example.com",
                    "breaches": [{"Name": "LinkedIn"}, {"Name": "Adobe"}],
                    "reputation": {},
                },
            )
        ]
        _execs, cands = translate_phase_messages(
            messages, phase="osint", scan_id="t", target="example.com"
        )
        leaks = [c for c in cands if c.type == InformationType.CREDENTIAL_LEAK]
        emails = [c for c in cands if c.type == InformationType.EMAIL]
        assert len(leaks) == 2
        assert any(c.normalized_value == "ann@example.com" for c in emails)
