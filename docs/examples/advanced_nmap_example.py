#!/usr/bin/env python3
"""
Example: Advanced Nmap Scanning

Demonstrates the enhanced Nmap capabilities with:
- Service version detection
- OS fingerprinting
- Vulnerability scanning
- NSE script execution
"""

import json
import sys

sys.path.insert(0, '/home/dasein/Work/projects/fackel/src')

from tools.nmap_scanner import nmap_port_scan


def print_section(title: str):
    """Print section header."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def example_basic_scan():
    """Example 1: Basic scan of a target."""
    print_section("Example 1: Basic Scan")
    
    target = "scanme.nmap.org"
    print(f"Target: {target}")
    print("Note: scanme.nmap.org is a host provided by Nmap for testing")
    print()
    
    result = nmap_port_scan.invoke({"host": target})
    
    if isinstance(result, dict):
        data = result.get('data', {})
        
        # Print summary
        summary = data.get('summary', {})
        print(f"✓ Scan complete:")
        print(f"  Total ports scanned: {summary.get('total_ports_scanned', 0)}")
        print(f"  Open ports: {summary.get('open_ports', 0)}")
        print(f"  Filtered ports: {summary.get('filtered_ports', 0)}")
        print(f"  Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"  OS detected: {summary.get('os_detected', False)}")
        
        # Print OS info
        os_info = data.get('os_info', {})
        if os_info.get('os_matches'):
            print(f"\n  Operating System:")
            for match in os_info['os_matches'][:3]:  # Top 3 matches
                print(f"    - {match['name']} ({match['accuracy']}%)")
        
        # Print services
        services = data.get('services', [])
        if services:
            print(f"\n  Open Services:")
            for svc in services[:5]:  # First 5 services
                if svc['state'] == 'open':
                    version = f"{svc['product']} {svc['version']}".strip()
                    print(f"    - Port {svc['port']}/{svc['protocol']}: {svc['service']}")
                    if version:
                        print(f"      Version: {version}")
                    if svc.get('vulnerabilities'):
                        print(f"      ⚠️  Vulnerabilities: {len(svc['vulnerabilities'])}")
    else:
        print(f"Result: {result}")


def example_vulnerability_details():
    """Example 2: Extract vulnerability details."""
    print_section("Example 2: Vulnerability Details")
    
    target = "scanme.nmap.org"
    print(f"Scanning {target} for vulnerabilities...")
    print()
    
    result = nmap_port_scan.invoke({"host": target})
    
    if isinstance(result, dict):
        data = result.get('data', {})
        services = data.get('services', [])
        
        vuln_count = 0
        for svc in services:
            vulnerabilities = svc.get('vulnerabilities', [])
            if vulnerabilities:
                print(f"Port {svc['port']}/{svc['protocol']} - {svc['service']}")
                print(f"  Product: {svc.get('product', 'unknown')} {svc.get('version', '')}")
                print(f"  Vulnerabilities:")
                
                for vuln in vulnerabilities[:3]:  # First 3 per service
                    vuln_count += 1
                    if 'id' in vuln:
                        cvss = vuln.get('cvss', 'N/A')
                        print(f"    - {vuln['id']} (CVSS: {cvss}) [{vuln['source']}]")
                    else:
                        print(f"    - {vuln.get('type', 'unknown')}")
                        if vuln.get('description'):
                            desc = vuln['description'][:80]
                            print(f"      {desc}...")
                print()
        
        if vuln_count == 0:
            print("✓ No vulnerabilities detected")


def example_full_output():
    """Example 3: Full structured output."""
    print_section("Example 3: Full Structured Output")
    
    target = "scanme.nmap.org"
    print(f"Scanning {target} and showing full output structure...")
    print()
    
    result = nmap_port_scan.invoke({"host": target})
    
    # Pretty print JSON
    print(json.dumps(result, indent=2, default=str))


def example_local_scan():
    """Example 4: Scan localhost (safe)."""
    print_section("Example 4: Localhost Scan")
    
    target = "127.0.0.1"
    print(f"Scanning localhost ({target})...")
    print("This is safe and won't trigger any IDS/IPS")
    print()
    
    result = nmap_port_scan.invoke({"host": target})
    
    if isinstance(result, dict):
        data = result.get('data', {})
        services = data.get('services', [])
        
        print(f"✓ Found {len(services)} ports")
        for svc in services:
            if svc['state'] == 'open':
                print(f"  Port {svc['port']}: {svc['service']} ({svc.get('product', 'unknown')})")


def main():
    """Run all examples."""
    print("\n" + "🔍 " * 20)
    print("Advanced Nmap Scanning Examples")
    print("🔍 " * 20)
    
    print("\n⚠️  Note: These examples use scanme.nmap.org, which is provided")
    print("   by Nmap.org specifically for testing. Do NOT scan other hosts")
    print("   without explicit authorization!\n")
    
    try:
        # Run examples
        example_basic_scan()
        example_vulnerability_details()
        example_local_scan()
        
        # Uncomment to see full output (verbose)
        # example_full_output()
        
        print("\n" + "=" * 60)
        print("✅ All examples completed!")
        print("=" * 60)
        
        print("\nNext steps:")
        print("  1. Review docs/advanced_nmap.md for all techniques")
        print("  2. Run with --active-scan: uv run fackel run target.com --active-scan")
        print("  3. For OS detection, run with sudo: sudo uv run fackel ...")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
