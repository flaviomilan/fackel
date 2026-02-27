Strategy: scan the IPs first (naabu → nmap). Then scan only
subdomains that might resolve to DIFFERENT IPs than those already
scanned. Skip subdomains that point to the same IP — the IP scan
already covers them.
