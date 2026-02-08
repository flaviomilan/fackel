import re

import nmap
from langchain.tools import tool


@tool
def nmap_port_scan(host: str):
    """Performs an active Nmap port/service scan and CVE lookup against a single host or IP address (structured response)."""
    try:
        nm = nmap.PortScanner()
        arguments = "-sV -T4 --script vulners"
        nm.scan(hosts=host, arguments=arguments)

        if not nm.all_hosts():
            return {
                "tool": "nmap_port_scan",
                "status": "error",
                "host": host,
                "error": "Host may be down or not responding.",
            }

        services = []
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                service = nm[host][proto][port]
                entry = {
                    "port": port,
                    "protocol": proto,
                    "state": service.get("state"),
                    "name": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "extra": service.get("extrainfo"),
                    "cves": [],
                }

                if "script" in service and "vulners" in service["script"]:
                    vulners_output = service["script"]["vulners"]
                    for match in re.finditer(r"(CVE-\d{4}-\d{4,7})\s*(\d+\.\d+)", vulners_output):
                        entry["cves"].append({"id": match.group(1), "cvss": float(match.group(2))})

                services.append(entry)

        return {
            "tool": "nmap_port_scan",
            "status": "ok",
            "host": host,
            "services": services,
        }

    except nmap.PortScannerError as e:
        return {
            "tool": "nmap_port_scan",
            "status": "error",
            "host": host,
            "error": f"Nmap execution error: {e}. Make sure Nmap is installed and in your system's PATH.",
        }
    except Exception as e:
        return {
            "tool": "nmap_port_scan",
            "status": "error",
            "host": host,
            "error": f"Unexpected error during Nmap scan: {e}",
        }
