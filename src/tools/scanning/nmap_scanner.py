"""Nmap port/service scanning with version detection and NSE vuln scripts."""

from __future__ import annotations

import os
import re
from typing import Any

import nmap
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    guard_target,
    require_binary,
    sanitize_ports,
)


def _is_root() -> bool:
    """Check if running with root/sudo privileges."""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _parse_os_info(nm, host: str) -> dict[str, Any]:
    """Extract OS detection information."""
    os_info = {
        "os_matches": [],
        "os_classes": [],
    }

    try:
        if "osmatch" in nm[host]:
            for osmatch in nm[host]["osmatch"]:
                os_info["os_matches"].append(
                    {
                        "name": osmatch.get("name", ""),
                        "accuracy": int(osmatch.get("accuracy", 0)),
                    }
                )

        if "osclass" in nm[host]:
            for osclass in nm[host]["osclass"]:
                os_info["os_classes"].append(
                    {
                        "type": osclass.get("type", ""),
                        "vendor": osclass.get("vendor", ""),
                        "osfamily": osclass.get("osfamily", ""),
                        "osgen": osclass.get("osgen", ""),
                        "accuracy": int(osclass.get("accuracy", 0)),
                    }
                )
    except (KeyError, ValueError):
        pass

    return os_info


def _parse_hostscript(nm, host: str) -> dict[str, Any]:
    """Extract host-level script results."""
    scripts = {}

    try:
        if "hostscript" in nm[host]:
            for script in nm[host]["hostscript"]:
                script_id = script.get("id", "unknown")
                scripts[script_id] = script.get("output", "")
    except KeyError:
        pass

    return scripts


def _extract_vulnerabilities(service: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract CVEs and vulnerabilities from service scripts."""
    vulnerabilities = []

    if "script" not in service:
        return vulnerabilities

    # Parse vulners output
    if "vulners" in service["script"]:
        vulners_output = service["script"]["vulners"]
        for match in re.finditer(r"(CVE-\d{4}-\d{4,7})\s*(\d+\.\d+)", vulners_output):
            vulnerabilities.append(
                {
                    "id": match.group(1),
                    "cvss": float(match.group(2)),
                    "source": "vulners",
                }
            )

    # Parse vulscan output (if present)
    if "vulscan" in service["script"]:
        vulscan_output = service["script"]["vulscan"]
        for match in re.finditer(r"(CVE-\d{4}-\d{4,7})", vulscan_output):
            cve_id = match.group(1)
            # Avoid duplicates
            if not any(v["id"] == cve_id for v in vulnerabilities):
                vulnerabilities.append(
                    {
                        "id": cve_id,
                        "source": "vulscan",
                    }
                )

    # Parse vuln script results
    vuln_scripts = ["http-vuln-", "ssl-", "ssh-", "smb-vuln-", "smtp-vuln-"]
    for script_name, script_output in service.get("script", {}).items():
        if any(script_name.startswith(prefix) for prefix in vuln_scripts) and (
            "VULNERABLE" in script_output or "vulnerable" in script_output.lower()
        ):
            vulnerabilities.append(
                {
                    "type": script_name.replace("http-vuln-", "").replace("smb-vuln-", ""),
                    "description": script_output[:200],  # First 200 chars
                    "source": "nse_script",
                }
            )

    return vulnerabilities


class NmapInput(BaseModel):
    """Input for nmap port/service scanner."""

    host: str = Field(
        description="IP address or domain to scan. One target per call.",
    )
    ports: str = Field(
        default="",
        description=(
            "Comma-separated ports or ranges (e.g. '22,80,443,8000-9000'). "
            "Feed ports discovered by naabu_scan here for targeted analysis. "
            "Leave empty for nmap's default top-1000 ports."
        ),
    )
    scan_type: str = Field(
        default="default",
        description=(
            "Scan intensity preset: "
            "'default' = version detection + vuln scripts + T4 timing; "
            "'quick' = version detection only, no vuln scripts (faster); "
            "'deep' = all 65535 ports, version intensity 9, all vuln scripts."
        ),
    )
    skip_host_discovery: bool = Field(
        default=False,
        description=(
            "Skip host discovery (-Pn). Use when the host drops ICMP "
            "or is behind a firewall that blocks ping probes."
        ),
    )


_VALID_SCAN_TYPES = frozenset({"default", "quick", "deep"})


def _build_scan_args(
    scan_type: str,
    ports: str,
    skip_host_discovery: bool,
) -> list[str]:
    """Build nmap CLI arguments from scan parameters."""
    if scan_type == "quick":
        args = [
            "-sV",
            "--version-intensity",
            "5",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "5m",
        ]
    elif scan_type == "deep":
        args = [
            "-sV",
            "--version-intensity",
            "9",
            "-sC",
            "--script",
            "vulners,vuln",
            "-T3",
            "--max-retries",
            "3",
            "--host-timeout",
            "20m",
        ]
        if not ports.strip():
            args.append("-p-")
    else:  # default
        args = [
            "-sV",
            "--version-intensity",
            "7",
            "-sC",
            "--script",
            "vulners,vuln",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "10m",
        ]

    if ports.strip():
        args.extend(["-p", ports.strip()])
    if skip_host_discovery:
        args.append("-Pn")
    if _is_root():
        args.extend(["-O", "--osscan-guess"])

    return args


def _parse_services(nm: Any, target: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse per-port service entries and summary counters from nmap results."""
    services: list[dict[str, Any]] = []
    open_ports = 0
    filtered_ports = 0
    total_vulns = 0

    for proto in nm[target].all_protocols():
        for port in sorted(nm[target][proto].keys()):
            service = nm[target][proto][port]
            state = service.get("state", "unknown")

            if state == "open":
                open_ports += 1
            elif state == "filtered":
                filtered_ports += 1

            vulnerabilities = _extract_vulnerabilities(service)
            total_vulns += len(vulnerabilities)

            entry: dict[str, Any] = {
                "port": port,
                "protocol": proto,
                "state": state,
                "service": service.get("name", "unknown"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "extrainfo": service.get("extrainfo", ""),
                "cpe": service.get("cpe", ""),
                "vulnerabilities": vulnerabilities,
                "scripts": {},
            }

            if "script" in service:
                for script_name, script_output in service["script"].items():
                    if script_name not in ["vulners", "vulscan"]:
                        entry["scripts"][script_name] = script_output[:500]

            services.append(entry)

    summary = {
        "total_ports_scanned": len(services),
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "total_vulnerabilities": total_vulns,
    }
    return services, summary


def _build_scan_result(nm: Any, target: str) -> dict[str, Any]:
    """Assemble the structured scan result dict from nmap output."""
    result: dict[str, Any] = {
        "target": target,
        "state": nm[target].state(),
        "hostnames": [],
        "addresses": {},
        "os_info": _parse_os_info(nm, target),
        "host_scripts": _parse_hostscript(nm, target),
        "services": [],
        "summary": {},
    }

    if "hostnames" in nm[target]:
        for hostname_entry in nm[target]["hostnames"]:
            if hostname_entry.get("name"):
                result["hostnames"].append(
                    {
                        "name": hostname_entry["name"],
                        "type": hostname_entry.get("type", "unknown"),
                    }
                )

    if "addresses" in nm[target]:
        result["addresses"] = nm[target]["addresses"]

    services, summary = _parse_services(nm, target)
    result["services"] = services
    summary["os_detected"] = len(result["os_info"].get("os_matches", [])) > 0
    result["summary"] = summary

    return result


@tool(args_schema=NmapInput)
def nmap_port_scan(
    host: str,
    ports: str = "",
    scan_type: str = "default",
    skip_host_discovery: bool = False,
) -> dict[str, Any]:
    """Advanced Nmap scan with version detection, OS fingerprinting, and NSE
    vulnerability scripts.

    Use for depth analysis after naabu has identified open ports.  Combines
    service version detection, default scripts, and vulnerability scanning.
    """
    target = guard_target(host, "nmap_port_scan", TargetType.HOST)

    require_binary("nmap", "nmap_port_scan")

    if scan_type not in _VALID_SCAN_TYPES:
        raise ToolException(
            f"nmap_port_scan: invalid scan_type {scan_type!r} — allowed: {', '.join(sorted(_VALID_SCAN_TYPES))}"
        )

    ports, ports_err = sanitize_ports(ports)
    if ports_err:
        raise ToolException(f"nmap_port_scan: {ports_err}")

    try:
        nm = nmap.PortScanner()
        arguments = " ".join(_build_scan_args(scan_type, ports, skip_host_discovery))
        nm.scan(hosts=target, arguments=arguments)

        if not nm.all_hosts():
            raise ToolException(
                "nmap_port_scan: Host may be down or not responding. Try with -Pn to skip host discovery."
            )

        return format_tool_output(
            "nmap_port_scan",
            host,
            "ok",
            data=_build_scan_result(nm, target),
        )

    except nmap.PortScannerError as e:
        raise ToolException(
            f"nmap_port_scan: Nmap execution error: {e}. Ensure Nmap is installed and accessible."
        ) from e
    except KeyError:
        raise ToolException(
            f"nmap_port_scan: Target {target} not found in scan results. Host may be down."
        ) from None
    except Exception as e:
        raise ToolException(f"nmap_port_scan: Unexpected error: {e}") from e


nmap_port_scan.handle_tool_error = True
