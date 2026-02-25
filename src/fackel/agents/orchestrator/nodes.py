"""Orchestrator graph nodes — thin wrappers that stream specialist ReAct agents.

Each node invokes its specialist agent via ``.stream()`` so that every
ReAct reasoning step (think → tool call → observe) can be surfaced to
the CLI in real-time.  Results are collected and returned as a partial
``ScanState`` update.

Architecture layers (per recommendation):
- **Input sanitiser** validates targets before they reach tools.
- **Output validator** checks tool results for structural correctness.
- **Max-iterations** guard prevents runaway ReAct loops.
- **Structured findings** — nodes always emit ``Finding`` dicts, never raw text.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, Literal

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command, interrupt

from fackel.tooling import is_reverse_ptr_subdomain, is_valid_domain, is_valid_ip, sanitize_target
from fackel.tooling.ip_classifier import classify_ip

from .evaluator import evaluate_phase
from .state import Finding, ScanState

logger = logging.getLogger(__name__)

# Type alias for the optional event callback injected by the CLI.
EventCallback = Callable[[str, str, dict[str, Any]], None] | None

# Module-level slot — set by the CLI before invoking the graph.
_event_callback: EventCallback = None

# Maximum ReAct iterations (tool calls) per agent invocation.
MAX_AGENT_ITERATIONS = 40

# Maximum number of subdomains propagated to downstream agents.
# Reverse-PTR entries are filtered first; this cap applies afterwards.
_SUBDOMAIN_CAP = 30


def set_event_callback(cb: EventCallback) -> None:
    """Set the callback that receives real-time ReAct events."""
    global _event_callback
    _event_callback = cb


# ── Helpers ────────────────────────────────────────────────────────────────


def _emit(phase: str, event_type: str, data: dict[str, Any]) -> None:
    """Notify the event callback if set."""
    if _event_callback is not None:
        _event_callback(phase, event_type, data)


def _make_finding(
    phase: str,
    title: str,
    detail: str,
    *,
    severity: Literal["critical", "high", "medium", "low", "info"] = "info",
    source_tool: str = "",
    confidence: float = 1.0,
) -> Finding:
    """Build a typed Finding dict."""
    return Finding(
        phase=phase,
        title=title,
        detail=detail,
        severity=severity,
        source_tool=source_tool,
        confidence=confidence,
    )


# ── Tool output validation ────────────────────────────────────────────────


def _validate_tool_output(msg: ToolMessage) -> ToolMessage:
    """Basic structural validation of tool results.

    Ensures the tool returned our standard envelope (``tool``, ``status``).
    Logs warnings for malformed or error outputs without blocking the agent.
    """
    try:
        payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        if isinstance(payload, dict):
            status = payload.get("status")
            if status == "error":
                logger.debug(
                    "tool %s returned error: %s",
                    msg.name,
                    payload.get("error", "unknown"),
                )
            elif "tool" not in payload:
                logger.debug(
                    "tool %s returned non-standard output (missing 'tool' key)",
                    msg.name,
                )
    except (json.JSONDecodeError, TypeError, AttributeError):
        logger.debug("tool %s returned non-JSON output", msg.name)
    return msg


# ── IP extraction ─────────────────────────────────────────────────────────


def _extract_ips_from_messages(messages: list[Any]) -> list[str]:
    """Pull IP addresses out of ToolMessage payloads from all OSINT tools.

    Handles the ``format_tool_output`` envelope and extracts IPs from:
    - ``dns_resolve`` — ``data.ips``
    - ``dnsdumpster_lookup`` — ``data.hosts[*].ip``
    - ``shodan_lookup`` — ``data.ip`` (host) / ``data.matches[*].ip`` (search)
    - ``censys_lookup`` — ``data.hosts[*].ip``
    """
    ips: list[str] = []

    def _add(value: object) -> None:
        ip_str = str(value).strip()
        if ip_str and ip_str not in ips and is_valid_ip(ip_str):
            ips.append(ip_str)

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue

            # Unwrap format_tool_output envelope → data dict
            inner = payload.get("data", payload)
            if not isinstance(inner, dict):
                continue

            # dns_resolve: {"ips": ["1.2.3.4", ...]}
            for ip in inner.get("ips", []):
                _add(ip)

            # dnsdumpster_lookup: {"hosts": [{"hostname": ..., "ip": "1.2.3.4"}, ...]}
            for host in inner.get("hosts", []):
                if isinstance(host, dict) and "ip" in host:
                    _add(host["ip"])

            # shodan_lookup (host mode): {"ip": "1.2.3.4", ...}
            if "ip" in inner and isinstance(inner["ip"], str):
                _add(inner["ip"])

            # shodan_lookup (search mode): {"matches": [{"ip": "1.2.3.4"}, ...]}
            for match in inner.get("matches", []):
                if isinstance(match, dict) and "ip" in match:
                    _add(match["ip"])
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return ips


# ── Subdomain extraction ──────────────────────────────────────────────────


def _extract_subdomains_from_messages(messages: list[Any], base_domain: str) -> list[str]:
    """Pull subdomain hostnames from ToolMessage payloads.

    Extracts from:
    - ``crtsh_subdomain_enum`` / ``virustotal_subdomain_enum`` / ``subfinder_enum`` — ``data.subdomains``
    - ``dnsdumpster_lookup`` — ``data.hosts[*].hostname``
    - ``subfinder_enum`` — ``data.details[*].subdomain`` (fallback)

    Filters out reverse-PTR-style subdomains (e.g. ``200-210-75-128.example.com``)
    that inflate the list without adding real scan value.
    """
    subs: list[str] = []
    base_lower = base_domain.lower()

    def _add(value: object) -> None:
        host = str(value).strip().lower().rstrip(".")
        if (
            host
            and host not in subs
            and host != base_lower
            and host.endswith(f".{base_lower}")
            and is_valid_domain(host)
            and not is_reverse_ptr_subdomain(host)
        ):
            subs.append(host)

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue

            inner = payload.get("data", payload)
            if not isinstance(inner, dict):
                continue

            # crtsh / virustotal / subfinder: {"subdomains": ["a.example.com", ...]}
            for sub in inner.get("subdomains", []):
                _add(sub)

            # dnsdumpster: {"hosts": [{"hostname": "sub.example.com", ...}, ...]}
            for host in inner.get("hosts", []):
                if isinstance(host, dict) and "hostname" in host:
                    _add(host["hostname"])

            # subfinder details fallback: {"details": [{"subdomain": "x.example.com"}, ...]}
            for detail in inner.get("details", []):
                if isinstance(detail, dict) and "subdomain" in detail:
                    _add(detail["subdomain"])
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return sorted(subs)


# ── IP classification extraction ──────────────────────────────────────────

# Maximum IPs to classify (avoids excessive API calls when many IPs found).
_IP_CLASS_CAP = 15


def _extract_ip_classifications_from_messages(
    messages: list[Any],
    target_domain: str,
) -> list[dict[str, Any]]:
    """Build IP classification entries from ipinfo/bgp ToolMessage payloads.

    For each IP that has an ipinfo_lookup result, the pure ``classify_ip``
    function determines the infrastructure class (cdn / cloud / direct_host
    / isp).  RIPEstat BGP data supplements when available.
    """
    # Collect raw per-IP data from tool outputs.
    ip_data: dict[str, dict] = {}  # ip → merged fields

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue
            inner = payload.get("data", payload)
            if not isinstance(inner, dict):
                continue
            tool_name = payload.get("tool", msg.name or "")
            ip_key = inner.get("ip", "")
            if not ip_key:
                continue

            entry = ip_data.setdefault(ip_key, {})

            if tool_name == "ipinfo_lookup":
                entry["org"] = inner.get("org", "")
                entry["asn"] = inner.get("asn", "")
                entry["hostname"] = inner.get("hostname", "")
                entry["anycast"] = inner.get("anycast", False)
                entry["city"] = inner.get("city", "")
                entry["country"] = inner.get("country", "")

            elif tool_name == "bgp_lookup":
                entry.setdefault("org", "")
                entry["asn_name"] = inner.get("asn_name", "")
                entry["asn_description"] = inner.get("asn_description", "")
                entry.setdefault("asn", inner.get("asn", ""))
                entry["prefix"] = inner.get("prefix", "")
                entry["rir"] = inner.get("rir", "")
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue

    # Run the classifier for each collected IP.
    classifications: list[dict[str, Any]] = []
    for ip, data in ip_data.items():
        ip_class = classify_ip(
            org=data.get("org", ""),
            asn=data.get("asn"),
            asn_name=data.get("asn_name", ""),
            hostname=data.get("hostname", ""),
            anycast=data.get("anycast", False),
            target_domain=target_domain,
        )
        classifications.append(
            {
                "ip": ip,
                "ip_class": ip_class,
                "org": data.get("org", ""),
                "asn": str(data.get("asn", "")),
                "asn_name": data.get("asn_name", ""),
                "country": data.get("country", ""),
                "anycast": data.get("anycast", False),
            }
        )
    return classifications


# ── Tech fingerprint extraction ───────────────────────────────────────────


def _extract_tech_fingerprints_from_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Build tech fingerprint entries from httpx_scan ToolMessage payloads.

    Each httpx result contains status code, server header, detected
    technologies, redirect chain, TLS info, etc.  We normalise these
    into a flat dict per probed target.
    """
    fingerprints: list[dict[str, Any]] = []
    seen: set[str] = set()

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue
            if payload.get("tool") != "httpx_scan":
                continue
            if payload.get("status") != "ok":
                continue

            inner = payload.get("data", {})
            results = inner.get("results", [])
            if not isinstance(results, list):
                continue

            for entry in results:
                if not isinstance(entry, dict):
                    continue
                url = entry.get("url", entry.get("input", ""))
                if not url or url in seen:
                    continue
                seen.add(url)

                techs = entry.get("tech", [])
                if isinstance(techs, str):
                    techs = [techs]

                fingerprints.append(
                    {
                        "target": url,
                        "host": entry.get("host", entry.get("input", "")),
                        "status_code": entry.get("status_code", entry.get("status-code")),
                        "server": entry.get("webserver", entry.get("server", "")),
                        "title": entry.get("title", ""),
                        "technologies": techs or [],
                        "content_type": entry.get("content_type", entry.get("content-type", "")),
                        "redirect_chain": entry.get("chain", []),
                        "tls": {
                            "version": entry.get("tls", {}).get("version", "")
                            if isinstance(entry.get("tls"), dict)
                            else "",
                            "cipher": entry.get("tls", {}).get("cipher", "")
                            if isinstance(entry.get("tls"), dict)
                            else "",
                        },
                        "cdn": entry.get("cdn", False),
                        "waf": entry.get("waf", ""),
                    }
                )
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return fingerprints


# ── Historical IP extraction from SecurityTrails ──────────────────────────


def _extract_historical_ips_from_messages(
    messages: list[Any],
    current_ips: list[str],
) -> list[str]:
    """Pull historical A-record IPs from securitytrails_history ToolMessages.

    Returns IPs that appear in historical A records but are **not** in
    *current_ips* — these are potential direct-origin candidates that may
    bypass CDN protection.  Deduplicates and validates each IP.
    """
    historical: list[str] = []

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue
            if payload.get("tool") != "securitytrails_history":
                continue
            if payload.get("status") != "ok":
                continue

            inner = payload.get("data", {})
            for record in inner.get("a_records", []):
                if not isinstance(record, dict):
                    continue
                ip_str = str(record.get("value", "")).strip()
                if (
                    ip_str
                    and ip_str not in historical
                    and ip_str not in current_ips
                    and is_valid_ip(ip_str)
                ):
                    historical.append(ip_str)
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return historical


# ── SAN extraction from TLS certificates ──────────────────────────────────


def _extract_san_domains_from_messages(messages: list[Any], base_domain: str) -> list[str]:
    """Pull SAN domains from tlscert_lookup ToolMessage payloads.

    Returns validated subdomain hostnames belonging to *base_domain*,
    deduplicated and sorted.  Wildcard prefixes (``*.``) are stripped
    before validation.
    """
    sans: list[str] = []
    base_lower = base_domain.lower()

    def _add(value: object) -> None:
        host = str(value).strip().lower().rstrip(".")
        if (
            host
            and host not in sans
            and host != base_lower
            and host.endswith(f".{base_lower}")
            and is_valid_domain(host)
            and not is_reverse_ptr_subdomain(host)
        ):
            sans.append(host)

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue
            if payload.get("tool") != "tlscert_lookup":
                continue
            if payload.get("status") != "ok":
                continue

            inner = payload.get("data", {})
            for san in inner.get("san_domains", []):
                _add(san)
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return sorted(sans)


def _run_and_stream_agent(agent, phase: str, user_message: str) -> list:
    """Stream a ReAct agent and emit events, returning all collected messages.

    Enforces ``MAX_AGENT_ITERATIONS`` — if the agent calls more tools than
    the limit, streaming stops to prevent runaway loops.
    """
    all_messages: list = []
    tool_call_count = 0
    _emit(phase, "start", {})

    for event in agent.stream(
        {"messages": [HumanMessage(content=user_message)]},
        stream_mode="updates",
    ):
        for _node_name, data in event.items():
            for msg in data.get("messages", []):
                # ── Output validation on tool results ──
                if isinstance(msg, ToolMessage):
                    msg = _validate_tool_output(msg)

                all_messages.append(msg)

                if isinstance(msg, AIMessage):
                    tool_calls = getattr(msg, "tool_calls", None)
                    if tool_calls:
                        for tc in tool_calls:
                            tool_call_count += 1
                            _emit(
                                phase,
                                "tool_call",
                                {
                                    "tool": tc["name"],
                                    "args": tc.get("args", {}),
                                },
                            )
                    elif msg.content:
                        _emit(phase, "reasoning", {"content": msg.content})

                elif isinstance(msg, ToolMessage):
                    # Distinguish tool errors from successful results.
                    _is_error = False
                    _error_hint = ""
                    try:
                        _pl = (
                            json.loads(msg.content) if isinstance(msg.content, str) else msg.content
                        )
                        if isinstance(_pl, dict) and _pl.get("status") == "error":
                            _is_error = True
                            _error_hint = str(_pl.get("error", "unknown"))
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass

                    if _is_error:
                        _emit(
                            phase,
                            "tool_error",
                            {
                                "tool": msg.name,
                                "error": _error_hint,
                            },
                        )
                    else:
                        _emit(
                            phase,
                            "tool_result",
                            {
                                "tool": msg.name,
                                "content": str(msg.content)[:500],
                            },
                        )

        # ── Max-iterations guard ──
        if tool_call_count >= MAX_AGENT_ITERATIONS:
            logger.warning(
                "%s: hit max iterations (%d tool calls) — stopping agent",
                phase,
                MAX_AGENT_ITERATIONS,
            )
            _emit(
                phase,
                "reasoning",
                {
                    "content": f"⚠ Agent stopped: reached {MAX_AGENT_ITERATIONS} tool call limit.",
                },
            )
            break

    return all_messages


def _agent_summary(messages: list[Any]) -> str:
    """Return the last AI message content, or a fallback."""
    for msg in reversed(messages):
        if (
            isinstance(msg, AIMessage)
            and msg.content
            and msg.content.strip()
            and not getattr(msg, "tool_calls", None)
        ):
            return msg.content.strip()
    return "No findings."


def _get_phase_evaluation(state: ScanState, phase: str) -> dict[str, Any] | None:
    """Retrieve the latest LLM-as-a-judge evaluation for *phase* from state."""
    for evaluation in reversed(state.get("phase_evaluations", [])):
        if isinstance(evaluation, dict) and evaluation.get("phase") == phase:
            return evaluation
    return None


# ── Nodes ──────────────────────────────────────────────────────────────────


def osint_node(state: ScanState) -> dict[str, Any]:
    """Run the OSINT ReAct agent for passive reconnaissance.

    Includes LLM-as-a-judge quality evaluation and self-reflection retry:
    if the first pass produces thin output (judge says "empty"), the agent
    is re-invoked with enriched instructions based on the judge's gaps.
    """
    from fackel.agents.osint.agent import build

    target = sanitize_target(state["target"])
    agent = build()

    # ── First agent pass ──
    messages = _run_and_stream_agent(
        agent, "osint", f"Perform passive OSINT reconnaissance on: {target}"
    )

    first_summary = _agent_summary(messages)

    # ── LLM-as-a-judge quality evaluation ──
    evaluation = evaluate_phase("osint", first_summary, [target])
    _emit(
        "osint",
        "evaluation",
        {
            "score": evaluation.score,
            "completeness": evaluation.completeness,
            "recommendation": evaluation.recommendation,
        },
    )

    # ── Self-reflection retry on poor quality ──
    if evaluation.completeness == "empty" and evaluation.score < 0.3:
        logger.info(
            "osint: judge rated output as empty (score=%.1f) — retrying with enriched prompt",
            evaluation.score,
        )
        gaps_text = "; ".join(evaluation.gaps) if evaluation.gaps else "thin output"
        retry_prompt = (
            f"Your first OSINT pass on {target} was insufficient.\n"
            f"Quality assessment: {evaluation.completeness} (score: {evaluation.score:.1f})\n"
            f"Gaps identified: {gaps_text}\n"
            f"Reasoning: {evaluation.reasoning}\n\n"
            f"Please perform a MORE THOROUGH reconnaissance on: {target}\n"
            "Use ALL available tools from your playbook — DNS, WHOIS, subdomain "
            "enumeration, reverse DNS, IP classification, Shodan/Censys, httpx, "
            "TLS certs. Do not stop after one or two tools."
        )
        _emit("osint", "retry", {"reason": gaps_text})
        retry_messages = _run_and_stream_agent(agent, "osint", retry_prompt)
        messages = messages + retry_messages  # merge for extraction

    ips = _extract_ips_from_messages(messages)
    if not ips and is_valid_ip(target):
        ips = [target]

    subdomains = (
        _extract_subdomains_from_messages(messages, target) if is_valid_domain(target) else []
    )

    # ── IP infrastructure classification ──
    classifications = _extract_ip_classifications_from_messages(messages, target)
    if classifications:
        class_lines = [
            f"  {c['ip']}: {c['ip_class']} ({c.get('org', 'unknown')})" for c in classifications
        ]
        logger.info(
            "osint: classified %d IP(s):\n%s",
            len(classifications),
            "\n".join(class_lines),
        )

    # ── HTTP tech fingerprints ──
    fingerprints = _extract_tech_fingerprints_from_messages(messages)
    if fingerprints:
        tech_lines = [
            f"  {fp['host']}: server={fp.get('server', '?')}, "
            f"tech={fp.get('technologies', [])} cdn={fp.get('cdn', False)}"
            for fp in fingerprints
        ]
        logger.info(
            "osint: fingerprinted %d target(s):\n%s",
            len(fingerprints),
            "\n".join(tech_lines),
        )

    # ── TLS certificate SAN enrichment ──
    if is_valid_domain(target):
        san_subs = _extract_san_domains_from_messages(messages, target)
        new_sans = [s for s in san_subs if s not in subdomains]
        if new_sans:
            subdomains = sorted(set(subdomains) | set(new_sans))
            logger.info(
                "osint: TLS SANs added %d new subdomain(s): %s",
                len(new_sans),
                ", ".join(new_sans),
            )

    # ── Historical DNS — direct-origin IP candidates ──
    historical_ips = _extract_historical_ips_from_messages(messages, ips)
    if historical_ips:
        ips = list(dict.fromkeys(ips + historical_ips))  # preserve order, dedup
        logger.info(
            "osint: historical DNS revealed %d direct-origin candidate(s): %s",
            len(historical_ips),
            ", ".join(historical_ips),
        )

    summary = _agent_summary(messages)
    _emit("osint", "summary", {"content": summary})
    _emit("osint", "done", {})
    return {
        "discovered_ips": ips,
        "discovered_subdomains": subdomains,
        "ip_classifications": classifications,
        "tech_fingerprints": fingerprints,
        "findings": [_make_finding("osint", "OSINT Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def port_scan_node(state: ScanState) -> dict[str, Any]:
    """Run the port-scan ReAct agent on discovered IPs and subdomains."""
    from fackel.agents.port_scan.agent import build

    target = state["target"]
    all_ips = state.get("discovered_ips", [])
    ips = [ip for ip in all_ips if ":" not in ip]
    dropped = len(all_ips) - len(ips)
    if dropped:
        logger.info("port_scan: dropping %d IPv6 address(es) — not yet supported", dropped)
    subdomains = state.get("discovered_subdomains", [])

    if not ips and not subdomains:
        return {
            "findings": [
                _make_finding(
                    "port_scan",
                    "Port Scan",
                    "No IPv4 targets available.",
                    severity="info",
                )
            ]
        }

    capped_subs = subdomains[:_SUBDOMAIN_CAP]
    skipped = len(subdomains) - len(capped_subs)

    parts = ["Scan the following targets for open ports and services."]
    parts.append(f"\nMain domain: {target}")
    if ips:
        parts.append(f"IPv4 addresses: {', '.join(ips)}")
    if capped_subs:
        parts.append(f"Discovered subdomains ({len(capped_subs)}): {', '.join(capped_subs)}")
    if skipped:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")

    # ── Include IP classification context when available ──
    ip_classes = {c["ip"]: c for c in state.get("ip_classifications", []) if c.get("ip") in ips}
    if ip_classes:
        parts.append("\nIP infrastructure classification (from OSINT):")
        for ip in ips:
            c = ip_classes.get(ip)
            if c:
                label = c.get("ip_class", "unknown")
                org = c.get("org", "")
                hint = ""
                if label == "cdn":
                    hint = " → CDN proxy, skip deep scanning (ports are the CDN's, not the origin)"
                elif label == "cloud":
                    hint = " → cloud-hosted, scan normally"
                elif label == "direct_host":
                    hint = " → direct infrastructure, HIGH PRIORITY"
                parts.append(f"  - {ip}: {label} ({org}){hint}")
        cdn_ips = [ip for ip, c in ip_classes.items() if c.get("ip_class") == "cdn"]
        if cdn_ips:
            parts.append(
                "\n⚠ CDN IPs detected. Scanning CDN proxy IPs (e.g. Cloudflare) "
                "yields the CDN's ports/services, not the origin server. "
                "Prioritise direct_host and cloud IPs instead."
            )

    parts.append(
        "\nStrategy: scan the IPs first (naabu → nmap). Then scan only "
        "subdomains that might resolve to DIFFERENT IPs than those already "
        "scanned. Skip subdomains that point to the same IP — the IP scan "
        "already covers them."
    )

    agent = build()
    messages = _run_and_stream_agent(agent, "port_scan", "\n".join(parts))

    summary = _agent_summary(messages)
    _emit("port_scan", "summary", {"content": summary})

    # ── LLM-as-a-judge quality evaluation ──
    scan_targets = ips + capped_subs
    evaluation = evaluate_phase("port_scan", summary, scan_targets)
    _emit(
        "port_scan",
        "evaluation",
        {
            "score": evaluation.score,
            "completeness": evaluation.completeness,
            "recommendation": evaluation.recommendation,
        },
    )

    _emit("port_scan", "done", {})
    return {
        "findings": [_make_finding("port_scan", "Port Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def report_node(state: ScanState) -> dict[str, Any]:
    """Generate the final pentest report via LLM."""
    from fackel.agents.report.agent import generate_report

    _emit("report", "start", {})
    report = generate_report(
        target=state["target"],
        active_scan=state["active_scan"],
        findings=state.get("findings", []),
        unassessed_areas=state.get("unassessed_areas", []),
        phase_evaluations=state.get("phase_evaluations", []),
        risk_score=state.get("risk_score"),
    )
    _emit("report", "done", {})
    return {"report": report}


def approval_gate(state: ScanState) -> Command:
    """Pause for human approval before active scanning.

    Uses LangGraph ``interrupt()`` to suspend execution.  The CLI (or API)
    resumes the graph with ``Command(resume=True/False)`` to approve or
    reject.
    """
    ips = state.get("discovered_ips", [])
    subdomains = state.get("discovered_subdomains", [])
    target = state["target"]

    _emit("approval", "start", {})

    summary_lines = [f"OSINT found {len(ips)} IP(s) for {target}: {', '.join(ips)}."]
    ip_classes = {c["ip"]: c for c in state.get("ip_classifications", [])}
    if ip_classes:
        for ip in ips:
            c = ip_classes.get(ip)
            if c:
                summary_lines.append(
                    f"  {ip}: {c.get('ip_class', '?')} ({c.get('org', 'unknown')})"
                )
    if subdomains:
        summary_lines.append(f"Subdomains ({len(subdomains)}): {', '.join(subdomains)}.")
    summary_lines.append("Proceed with active scanning (port scan + vuln scan)?")

    approved = interrupt(
        {
            "question": "\n".join(summary_lines),
            "targets": ips,
            "subdomains": subdomains,
        }
    )

    _emit("approval", "done", {"approved": approved})

    if approved:
        return Command(goto="port_scan")
    return Command(goto="report")


def vuln_scan_node(state: ScanState) -> dict[str, Any]:
    """Run the vuln-scan ReAct agent on the target domain, subdomains, and IPs."""
    from fackel.agents.vuln_scan.agent import build

    target = state["target"]
    all_ips = state.get("discovered_ips", [])
    ips = [ip for ip in all_ips if ":" not in ip]
    dropped = len(all_ips) - len(ips)
    if dropped:
        logger.info("vuln_scan: dropping %d IPv6 address(es) — not yet supported", dropped)
    subdomains = state.get("discovered_subdomains", [])

    capped_subs = subdomains[:_SUBDOMAIN_CAP]
    skipped = len(subdomains) - len(capped_subs)

    parts = ["Run vulnerability scans on the target."]
    parts.append(f"\nOriginal target domain: {target}")
    if capped_subs:
        parts.append(f"Discovered subdomains ({len(capped_subs)}): {', '.join(capped_subs)}")
    if skipped:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")
    if ips:
        parts.append(f"Discovered IPv4 addresses: {', '.join(ips)}")
    else:
        parts.append("No IPv4 addresses were discovered.")

    # ── Include technology fingerprints from OSINT httpx probing ──
    tech_fps = state.get("tech_fingerprints", [])
    if tech_fps:
        parts.append("\nTechnology fingerprints (from OSINT httpx scan):")
        for fp in tech_fps[:10]:  # cap to avoid prompt bloat
            host = fp.get("host", fp.get("target", "?"))
            server = fp.get("server", "")
            techs = fp.get("technologies", [])
            waf = fp.get("waf", "")
            cdn = fp.get("cdn", False)
            line = f"  - {host}: server={server or '?'}"
            if techs:
                line += f", tech=[{', '.join(techs[:8])}]"
            if cdn:
                line += ", CDN=yes"
            if waf:
                line += f", WAF={waf}"
            parts.append(line)
        all_techs = sorted({t for fp in tech_fps for t in fp.get("technologies", [])})
        if all_techs:
            parts.append(
                f"\nDetected technologies: {', '.join(all_techs)}. "
                "Prioritise nuclei templates targeting these specific "
                "technologies for higher-value findings."
            )

    # ── Adapt strategy from port_scan evaluation ──
    port_eval = _get_phase_evaluation(state, "port_scan")
    if port_eval:
        completeness = port_eval.get("completeness", "partial")
        if completeness == "empty":
            parts.append(
                "\n⚠ PORT SCAN FOUND NO OPEN PORTS. Focus entirely on "
                "domain-level checks: nuclei templates (DNS, SSL, HTTP), "
                "wafw00f, httpx, and katana on the domain and subdomains. "
                "Do NOT waste iterations on IP-specific scans."
            )
        elif completeness == "partial":
            eval_gaps = port_eval.get("gaps", [])
            if eval_gaps:
                gaps_str = "; ".join(eval_gaps)
                parts.append(f"\n⚠ Port scan gaps: {gaps_str}")
            parts.append(
                "\nPort scan was partial. Prioritise domain-level nuclei "
                "and httpx. Run IP-specific checks only if ports were found "
                "on that IP."
            )
        else:  # complete
            parts.append(
                "\nScan the DOMAIN first (nuclei with empty severity for full "
                "template coverage). Then scan the most interesting subdomains "
                "(www, web apps, APIs, panels). Then per-IP checks. Prioritise "
                "breadth — it's better to scan more targets shallowly than "
                "fewer targets deeply."
            )
    else:
        parts.append(
            "\nScan the DOMAIN first (nuclei with empty severity for full template "
            "coverage). Then scan the most interesting subdomains (www, web apps, "
            "APIs, panels). Then per-IP checks. Prioritise breadth — it's better "
            "to scan more targets shallowly than fewer targets deeply."
        )

    agent = build()
    messages = _run_and_stream_agent(agent, "vuln_scan", "\n".join(parts))

    summary = _agent_summary(messages)
    _emit("vuln_scan", "summary", {"content": summary})

    # ── LLM-as-a-judge quality evaluation ──
    scan_targets = [target, *capped_subs, *ips]
    evaluation = evaluate_phase("vuln_scan", summary, scan_targets)
    _emit(
        "vuln_scan",
        "evaluation",
        {
            "score": evaluation.score,
            "completeness": evaluation.completeness,
            "recommendation": evaluation.recommendation,
        },
    )

    _emit("vuln_scan", "done", {})
    return {
        "findings": [_make_finding("vuln_scan", "Vulnerability Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def triage_node(state: ScanState) -> dict[str, Any]:
    """Analyse findings and identify unassessed areas via structured LLM output.

    Passes structured state context (IP classifications, tech fingerprints,
    phase evaluations) alongside textual findings so the triage LLM can
    produce evidence-backed risk scores from machine-readable data.
    """
    from fackel.agents.triage.agent import run_triage

    _emit("triage", "start", {})

    findings = state.get("findings", [])
    result = run_triage(
        findings,
        ip_classifications=state.get("ip_classifications", []),
        tech_fingerprints=state.get("tech_fingerprints", []),
        phase_evaluations=state.get("phase_evaluations", []),
    )

    unassessed = [
        {
            "technology": area.technology,
            "detected_by": area.detected_by,
            "reason": area.reason,
            "recommendation": area.recommendation,
        }
        for area in result.unassessed_areas
    ]

    risk = result.risk_score
    risk_dict = {
        "score": risk.score,
        "exposure_type": risk.exposure_type,
        "factors": list(risk.factors),
    }

    summary_parts = [f"## Triage Summary\n\n{result.summary}"]
    summary_parts.append(f"\n**Risk Score:** {risk.score:.1f}/10 ({risk.exposure_type})")
    if risk.factors:
        summary_parts.append("\n**Risk Factors:**\n" + "\n".join(f"- {f}" for f in risk.factors))
    if result.technologies_detected:
        techs = ", ".join(result.technologies_detected)
        summary_parts.append(f"\n**Technologies detected:** {techs}")
    if unassessed:
        names = ", ".join(a["technology"] for a in unassessed)
        summary_parts.append(f"\n**Unassessed areas:** {names}")

    triage_detail = "\n".join(summary_parts)

    _emit("triage", "summary", {"content": triage_detail})
    _emit(
        "triage",
        "done",
        {
            "technologies": result.technologies_detected,
            "unassessed_count": len(unassessed),
            "risk_score": risk.score,
            "risk_exposure_type": risk.exposure_type,
        },
    )

    return {
        "findings": [_make_finding("triage", "Triage Summary", triage_detail)],
        "unassessed_areas": unassessed,
        "risk_score": risk_dict,
    }


# ── Routing ────────────────────────────────────────────────────────────────


def route_after_osint(state: ScanState) -> str:
    """Decide next step: approval gate (active) or straight to report (passive)."""
    if not state.get("active_scan"):
        return "report"
    all_ips = state.get("discovered_ips", [])
    ipv4 = [ip for ip in all_ips if ":" not in ip]
    dropped = len(all_ips) - len(ipv4)
    if dropped:
        logger.info("route_after_osint: dropping %d IPv6 address(es) — not yet supported", dropped)
    has_scan_targets = bool(ipv4) or bool(state.get("discovered_subdomains"))
    return "approval_gate" if has_scan_targets else "report"


def route_after_port_scan(state: ScanState) -> str:
    """Route after port scan: vuln_scan normally, or skip to triage if empty.

    Uses the LLM-as-a-judge evaluation stored in state by ``port_scan_node``.
    Only skips to triage when the judge explicitly recommends it — default
    is to proceed to vuln_scan (which can still find domain-level issues).
    """
    port_eval = _get_phase_evaluation(state, "port_scan")
    if port_eval and port_eval.get("recommendation") == "skip_downstream":
        logger.info("routing: port_scan judge recommends skip → triage")
        return "triage"
    return "vuln_scan"
