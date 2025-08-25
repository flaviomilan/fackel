import re

import nmap
from langchain.tools import tool


@tool
def nmap_port_scan(host: str) -> str:
    """Performs an active Nmap port/service scan and CVE lookup against a single host or IP address.
    This powerful tool discovers open ports, running services, their versions, and associated CVEs.
    WARNING: This is an ACTIVE scanning tool. It can be detected by the target.
    Only use it on targets you have explicit permission to scan.
    """
    try:
        nm = nmap.PortScanner()
        # -sV: Probe open ports to determine service/version info
        # -T4: Aggressive timing template (for faster scans)
        # --script vulners: Check for vulnerabilities using the Vulners database
        arguments = "-sV -T4 --script vulners"
        nm.scan(hosts=host, arguments=arguments)

        if not nm.all_hosts():
            return f"Nmap scan on {host} failed. Host may be down or not responding."

        output = [f"Nmap scan report for {host}:"]
        output.append(f"Host Status: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            output.append(f"\nProtocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service = nm[host][proto][port]
                port_info = f"\n  Port: {port}"
                port_info += f"\n    State: {service['state']}"
                port_info += f"\n    Service: {service['name']}"
                port_info += f"\n    Product: {service.get('product', 'N/A')}"
                port_info += f"\n    Version: {service.get('version', 'N/A')}"
                port_info += f"\n    Extra Info: {service.get('extrainfo', 'N/A')}"
                output.append(port_info)

                if "script" in service and "vulners" in service["script"]:
                    output.append(f"    **Vulnerabilities (CVEs) Found:**")

                    vulners_output = service["script"]["vulners"]

                    cve_matches = re.finditer(
                        r"(CVE-\d{4}-\d{4,7})\s*(\d+\.\d+)", vulners_output
                    )
                    found_cves = False
                    for match in cve_matches:
                        cve_id = match.group(1)
                        cvss_score = match.group(2)
                        output.append(f"      - {cve_id} (CVSS: {cvss_score})")
                        found_cves = True

                    if not found_cves:
                        output.append(
                            "      - No specific CVEs listed by Vulners, but vulnerabilities may exist."
                        )

        return "\n".join(output)

    except nmap.PortScannerError as e:
        return f"Nmap execution error: {e}. Make sure Nmap is installed and in your system's PATH."
    except Exception as e:
        return f"An unexpected error occurred during the Nmap scan: {e}"
