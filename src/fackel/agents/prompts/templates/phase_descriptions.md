## osint

The OSINT phase performs passive reconnaissance — DNS lookups,
WHOIS, subdomain enumeration, TLS certificates, Shodan/Censys,
and more.  You can provide guidance on what aspects to focus on,
targets to prioritise, or tools to skip.

## port_scan

The port scan phase will actively scan discovered IPs and
subdomains for open ports and services.  You can guide which
hosts to prioritise, scan depth, or ports to focus on.

## vuln_scan

The vulnerability scan phase runs nuclei, dalfox, wpscan and
other tools against discovered services.  You can direct which
vulnerabilities to look for, technologies to focus on, or tools
to skip.
