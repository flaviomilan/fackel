"""Translator tests for OSINT, port-scan, and vuln-scan phases."""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage, ToolMessage

from fackel.agents.orchestrator.translators import translate_phase_messages
from fackel.agents.orchestrator.translators.translators import (
    extract_tool_executions,
    translate_osint,
    translate_port_scan,
    translate_vuln_scan,
)
from fackel.domain import InformationType, ToolExecutionStatus


def _tool_msg(tool: str, data: dict, *, call_id: str = "call-1") -> ToolMessage:
    return ToolMessage(
        content=json.dumps({"tool": tool, "status": "ok", "data": data}),
        tool_call_id=call_id,
        name=tool,
    )


def test_translate_osint_extracts_subdomains_and_ips() -> None:
    msg = _tool_msg(
        "subfinder",
        {
            "subdomains": ["api.example.com", "www.example.com", "other.com"],
            "ips": ["1.2.3.4", "not-an-ip"],
        },
    )
    candidates = translate_osint([msg], target="example.com")

    by_type: dict[InformationType, list[str]] = {}
    for c in candidates:
        by_type.setdefault(c.type, []).append(c.normalized_value)

    assert "api.example.com" in by_type.get(InformationType.SUBDOMAIN, [])
    assert "www.example.com" in by_type.get(InformationType.SUBDOMAIN, [])
    assert "other.com" not in by_type.get(InformationType.SUBDOMAIN, [])
    assert "1.2.3.4" in by_type.get(InformationType.IP_ADDRESS, [])
    assert "not-an-ip" not in by_type.get(InformationType.IP_ADDRESS, [])


def test_translate_port_scan_extracts_open_ports_and_services() -> None:
    msg = _tool_msg(
        "naabu_scan",
        {
            "host": "example.com",
            "ports": [
                {
                    "host": "example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "version": "nginx/1.25",
                },
                {"port": "not-a-number"},
            ],
        },
    )
    candidates = translate_port_scan([msg])

    types = {(c.type, c.normalized_value) for c in candidates}
    assert (InformationType.OPEN_PORT, "example.com:443/tcp") in types
    assert any(t == InformationType.SERVICE_VERSION for t, _ in types)


def test_translate_vuln_scan_extracts_vulnerabilities() -> None:
    msg = _tool_msg(
        "nuclei_scan",
        {
            "findings": [
                {
                    "template-id": "CVE-2024-9999",
                    "host": "https://example.com",
                    "matched-at": "https://example.com/admin",
                    "severity": "high",
                }
            ]
        },
    )
    candidates = translate_vuln_scan([msg])
    assert candidates, "expected at least one vulnerability candidate"
    assert all(c.type == InformationType.SECURITY_VULNERABILITY for c in candidates)


def test_extract_tool_executions_pairs_params_with_tool_calls() -> None:
    ai = AIMessage(
        content="",
        tool_calls=[
            {
                "id": "call-xyz",
                "name": "subfinder",
                "args": {"domain": "example.com"},
            }
        ],
    )
    tool_msg = _tool_msg("subfinder", {"subdomains": []}, call_id="call-xyz")

    executions = extract_tool_executions([ai, tool_msg], scan_id="scan-1", phase="osint")
    assert len(executions) == 1
    exec_ = executions[0]
    assert exec_.tool_name == "subfinder"
    assert exec_.params == {"domain": "example.com"}
    assert exec_.status == ToolExecutionStatus.OK
    assert exec_.execution_id == "call-xyz"


def test_translate_phase_messages_dispatches_per_phase() -> None:
    msg = _tool_msg("subfinder", {"subdomains": ["api.example.com"]})
    executions, candidates = translate_phase_messages(
        [msg], phase="osint", scan_id="scan-1", target="example.com"
    )
    assert len(executions) == 1
    assert any(c.type == InformationType.SUBDOMAIN for c in candidates)

    executions, candidates = translate_phase_messages(
        [msg], phase="unknown_phase", scan_id="scan-1", target="example.com"
    )
    assert candidates == []
