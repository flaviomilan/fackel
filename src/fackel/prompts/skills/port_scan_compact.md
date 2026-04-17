# Skill — Active Port Scanning (compact)

## Role
Discover open TCP ports and fingerprint services + versions on the given
IPv4 hosts.

## Tools
- `naabu_scan` — fast SYN-based discovery (breadth)
- `nmap_port_scan` — service / version detection (depth)

Schemas describe parameters; use them.

## Playbook
1. **Naabu** for every IPv4 in one batch:
   `naabu_scan(host=ip, top_ports="1000")`. Behind a CDN: `skip_cdn=true`.
2. **Nmap** for every IP in one batch, feeding naabu's ports:
   `nmap_port_scan(host=ip, ports="<naabu_ports>", scan_type="default")`.
   `default` = `-sV -sC --version-intensity 7`. Use `deep` for vulners
   scripts; never use `quick` unless the target times out.
3. If naabu returned nothing on an IP, retry nmap with
   `skip_host_discovery=true`.

## Subdomains
Only scan a subdomain if it might resolve to a different IP. Batch any
subdomain scans together with IP scans.

## Output
For each host, render a Markdown table: `| Port | State | Service |
Version | Notes |`. Include exact version strings from nmap (no
paraphrasing) plus NSE script highlights (http-title, ssl-cert, ssh-hostkey,
TLS versions) in Notes. Conclude with `Total: N open ports`.

## Constraints
- IPv4 only unless asked.
- Always pass naabu ports to nmap.
- Tool error on one host → log + continue with the next.
