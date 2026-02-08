import re
import os
from urllib.parse import urlparse


import nmap
from langchain.tools import tool

from .utils import format_tool_output


def _is_root() -> bool:
    """Check if running with root/sudo privileges."""
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def _parse_os_info(nm, host: str) -> dict:
    """Extract OS detection information."""
    os_info = {
        "os_matches": [],
        "os_classes": [],
    }
    
    try:
        if 'osmatch' in nm[host]:
            for osmatch in nm[host]['osmatch']:
                os_info['os_matches'].append({
                    'name': osmatch.get('name', ''),
                    'accuracy': int(osmatch.get('accuracy', 0)),
                })
        
        if 'osclass' in nm[host]:
            for osclass in nm[host]['osclass']:
                os_info['os_classes'].append({
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'osfamily': osclass.get('osfamily', ''),
                    'osgen': osclass.get('osgen', ''),
                    'accuracy': int(osclass.get('accuracy', 0)),
                })
    except (KeyError, ValueError):
        pass
    
    return os_info


def _parse_hostscript(nm, host: str) -> dict:
    """Extract host-level script results."""
    scripts = {}
    
    try:
        if 'hostscript' in nm[host]:
            for script in nm[host]['hostscript']:
                script_id = script.get('id', 'unknown')
                scripts[script_id] = script.get('output', '')
    except KeyError:
        pass
    
    return scripts


def _extract_vulnerabilities(service: dict) -> list:
    """Extract CVEs and vulnerabilities from service scripts."""
    vulnerabilities = []
    
    if 'script' not in service:
        return vulnerabilities
    
    # Parse vulners output
    if 'vulners' in service['script']:
        vulners_output = service['script']['vulners']
        for match in re.finditer(r"(CVE-\d{4}-\d{4,7})\s*(\d+\.\d+)", vulners_output):
            vulnerabilities.append({
                'id': match.group(1),
                'cvss': float(match.group(2)),
                'source': 'vulners',
            })
    
    # Parse vulscan output (if present)
    if 'vulscan' in service['script']:
        vulscan_output = service['script']['vulscan']
        for match in re.finditer(r"(CVE-\d{4}-\d{4,7})", vulscan_output):
            cve_id = match.group(1)
            # Avoid duplicates
            if not any(v['id'] == cve_id for v in vulnerabilities):
                vulnerabilities.append({
                    'id': cve_id,
                    'source': 'vulscan',
                })
    
    # Parse vuln script results
    vuln_scripts = ['http-vuln-', 'ssl-', 'ssh-', 'smb-vuln-', 'smtp-vuln-']
    for script_name, script_output in service.get('script', {}).items():
        if any(script_name.startswith(prefix) for prefix in vuln_scripts):
            # Check if vulnerable
            if 'VULNERABLE' in script_output or 'vulnerable' in script_output.lower():
                vulnerabilities.append({
                    'type': script_name.replace('http-vuln-', '').replace('smb-vuln-', ''),
                    'description': script_output[:200],  # First 200 chars
                    'source': 'nse_script',
                })
    
    return vulnerabilities


@tool
def nmap_port_scan(host: str):
    """
    Performs an advanced Nmap port/service scan with version detection,
    OS fingerprinting, and vulnerability assessment.
    
    Features:
    - Service version detection with high intensity
    - OS detection (when privileges allow)
    - NSE vulnerability scripts (vulners, vuln category)
    - Default safe scripts for information gathering
    - CPE (Common Platform Enumeration) detection
    - Aggressive timing for faster scans
    
    Returns structured data with services, versions, OS info, and CVEs.
    """
    parsed = urlparse(host)
    target = parsed.netloc or parsed.path or host
    if not target:
        return format_tool_output(
            "nmap_port_scan",
            host,
            "error",
            error="Invalid target",
        )
    
    # Remove port from target if present
    target = target.split(':')[0]
    
    try:
        nm = nmap.PortScanner()
        
        # Build advanced Nmap arguments
        args = [
            "-sV",  # Service version detection
            "--version-intensity", "7",  # Aggressive version detection (0-9, default 7)
            "-sC",  # Default NSE scripts (safe and useful)
            "--script", "vulners,vuln",  # Vulnerability detection scripts
            "-T4",  # Aggressive timing template
            "--max-retries", "2",  # Limit retries for faster scans
            "--host-timeout", "10m",  # 10 minute timeout per host
        ]
        
        # Add OS detection if running with privileges
        if _is_root():
            args.extend(["-O", "--osscan-guess"])  # OS detection with guessing
        
        # Port range: scan top 1000 ports (default) for speed
        # For full scan, could use -p- but very slow
        
        arguments = " ".join(args)
        
        nm.scan(hosts=target, arguments=arguments)

        if not nm.all_hosts():
            return format_tool_output(
                "nmap_port_scan",
                host,
                "error",
                error="Host may be down or not responding. Try with -Pn to skip host discovery.",
            )

        scan_result = {
            "target": target,
            "state": nm[target].state(),
            "hostnames": [],
            "addresses": {},
            "os_info": {},
            "host_scripts": {},
            "services": [],
            "summary": {},
        }
        
        # Extract hostnames
        if 'hostnames' in nm[target]:
            for hostname_entry in nm[target]['hostnames']:
                if hostname_entry.get('name'):
                    scan_result['hostnames'].append({
                        'name': hostname_entry['name'],
                        'type': hostname_entry.get('type', 'unknown'),
                    })
        
        # Extract addresses
        if 'addresses' in nm[target]:
            scan_result['addresses'] = nm[target]['addresses']
        
        # Extract OS information (if available)
        scan_result['os_info'] = _parse_os_info(nm, target)
        
        # Extract host-level scripts
        scan_result['host_scripts'] = _parse_hostscript(nm, target)
        
        # Extract service information
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
                
                # Extract vulnerabilities
                vulnerabilities = _extract_vulnerabilities(service)
                total_vulns += len(vulnerabilities)
                
                entry = {
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", ""),
                    "cpe": service.get("cpe", ""),  # Common Platform Enumeration
                    "vulnerabilities": vulnerabilities,
                    "scripts": {},
                }
                
                # Extract non-vulnerability script results
                if 'script' in service:
                    for script_name, script_output in service['script'].items():
                        # Skip vuln scripts (already processed)
                        if script_name not in ['vulners', 'vulscan']:
                            entry['scripts'][script_name] = script_output[:500]  # Truncate to 500 chars
                
                scan_result['services'].append(entry)
        
        # Add summary statistics
        scan_result['summary'] = {
            'total_ports_scanned': len(scan_result['services']),
            'open_ports': open_ports,
            'filtered_ports': filtered_ports,
            'total_vulnerabilities': total_vulns,
            'os_detected': len(scan_result['os_info'].get('os_matches', [])) > 0,
        }

        return format_tool_output(
            "nmap_port_scan",
            host,
            "ok",
            data=scan_result,
        )

    except nmap.PortScannerError as e:
        return format_tool_output(
            "nmap_port_scan",
            host,
            "error",
            error=f"Nmap execution error: {e}. Ensure Nmap is installed and accessible.",
        )
    except KeyError as e:
        return format_tool_output(
            "nmap_port_scan",
            host,
            "error",
            error=f"Target {target} not found in scan results. Host may be down.",
        )
    except Exception as e:
        return format_tool_output(
            "nmap_port_scan",
            host,
            "error",
            error=f"Unexpected error: {e}",
        )
