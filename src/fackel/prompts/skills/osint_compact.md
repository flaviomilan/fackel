# Skill — Passive OSINT (compact)

## Role
Passive reconnaissance + lightweight HTTP/TLS fingerprinting on the given
target. No port scanning, no exploitation, no brute-forcing.

## Tool catalog
The full tool list with parameters is visible in your tool schema. Use what
is available; skip silently if a tool is missing. Group by purpose:

- **Resolution / WHOIS**: `dns_resolve`, `whois_lookup`, `tlscert_lookup`,
  `reverse_dns_lookup`
- **Subdomain enum**: `subfinder_enum`, `amass_enum`, `chaos_enum`,
  `crtsh_subdomain_enum`, `dnsdumpster_lookup`, `virustotal_subdomain_enum`;
  validate with `dnsx_resolve`
- **IP enrichment**: `ipinfo_lookup`, `bgp_lookup`, `greynoise_lookup`,
  `abuseipdb_lookup`, `internetdb_lookup` (free,
  no key), `shodan_lookup`, `censys_lookup`, `fofa_search`, `netlas_lookup`
- **HTTP / tech**: `httpx_scan`, `whatweb_scan`
- **Historical / passive intel**: `securitytrails_history`, `urlscan_search`,
  `otx_passive_dns`, `gau_urls`
- **Surface discovery**: `paramspider_crawl`, `linkfinder_extract`,
  `document_search`, `cloudbrute_enum`, `js_secret_scan`,
  `github_repo_discovery` → `trufflehog_scan`,
  `subzy_check`
- **People / context**: `job_search`, `hunter_email_search` → `analyze_email`,
  `breach_lookup`; `maigret_scan` (username → social, semi-passive/opt-in)

## Playbook (all batches run in parallel)

1. **DNS + WHOIS**: `dns_resolve(target)` + `whois_lookup(domain)`.
2. **Subdomains**: prefer `subfinder_enum(all_sources=true)` (covers crt.sh +
   VirusTotal + 40 sources) + `amass_enum` + `crtsh_subdomain_enum`. Treat
   `dnsdumpster`/`virustotal` as supplementary. Never skip all if one failed.
   Then validate the set with `dnsx_resolve(hosts, wildcard_domain)` — resolves
   all, filters wildcards, flags unresolved names as takeover candidates.
3. **Per-IP enrichment**: for each unique IPv4 from step 1, batch
   `reverse_dns_lookup`, `ipinfo_lookup`, `bgp_lookup`, `internetdb_lookup`
   (free, no key). If keys exist: `shodan_lookup`, `censys_lookup`, `fofa_search`.
4. **HTTP / TLS / historical** on the main domain in one batch:
   `httpx_scan(tech_detect=true)`, `whatweb_scan`, `tlscert_lookup`,
   `securitytrails_history`, `urlscan_search`, `otx_passive_dns`.
5. **Surface discovery** in one batch (when applicable):
   `gau_urls`, `paramspider_crawl`, `linkfinder_extract` on main JS,
   `cloudbrute_enum(<brand>)`, `github_repo_discovery(<org>)` → then
   `trufflehog_scan(<repo_url>)`, `hunter_email_search(domain)` →
   `analyze_email(email)`, `job_search(company)`.
6. **Subzy** on the discovered subdomain set.
7. **Subdomain deep-dive** (≤5 interesting subs: www/api/app/admin/staging):
   `httpx_scan` + `tlscert_lookup` per sub, batched.

If the target is already an IP: skip DNS, subdomain enum, historical DNS,
job search; keep WHOIS, reverse_dns, ipinfo, httpx, tlscert, shodan/censys.

## Argument rules
- IP-only tools (shodan/censys/reverse_dns/ipinfo/bgp): pass IPs.
- Domain-only tools (subfinder/amass/crtsh/virustotal/dnsdumpster/securitytrails):
  pass domain names.
- Deduplicate subdomains across sources before reporting.

## Signals & anomalies (flag when seen)

- CNAME→CDN: resolved IP is the CDN's, not origin. Multiple A = round-robin/anycast.
- Subdomain with no DNS → dangling CNAME → `subzy_check` (takeover). `dev-/staging-/
  test-/*.corp.*` names = internal, high priority. >500 subs = wildcard, verify.
- TLS SANs reveal hidden subdomains; expired/self-signed/`*.corp.*` cert = misconfig.
- WHOIS near-expiry or recently changed = hijack risk. Private IPs: don't query ASN.
- Unusual ports (4444/6666/31337) = possible backdoor. Record exact tech versions for
  CVEs (jQuery<3.5 = XSS). Verbose Server/X-Powered-By = info disclosure.
- Public/read cloud bucket = exposure (write = critical). TruffleHog verified secret =
  critical, unverified = high. JS secrets: AWS/GitHub/Stripe/private-key = critical;
  Slack/JWT/password = high; generic-key/internal-IP/Firebase/S3 = medium.
- Single-source reputation/IOC data is informational — corroborate.

**Quality bar:** ≥3 subdomain sources, every IP enriched (ipinfo+bgp), httpx on main
domain, WHOIS, TLS cert, and `subzy_check` run — or document why not.

## Output (Markdown summary)

Use a labelled section per area. Always include when present:

- **Target / IPv4 / IPv6 / Registrar / NS / Created+Expires**
- **Subdomains** with sources and resolutions; flag ones with no IP.
- **Per-IP**: PTR, shared_domains count, ASN, org, anycast, classification
  (`cdn|cloud|direct_host|isp`). If shared_domains > 5, flag as multi-tenancy
  risk.
- **Shodan / Censys / FOFA** banners, ports, hostnames per IP.
- **HTTP fingerprint** per host: status, server, tech, redirect chain.
- **TLS** per host: issuer, CN, SAN count, fingerprint, validity.
- **Historical DNS** (A/MX/NS) with first/last seen; flag old IPs that
  still resolve as direct-origin candidates.
- **Urlscan / OTX / gau** highlights; **paramspider** parameter list;
  **linkfinder** API routes; **subzy** takeover candidates;
  **whatweb** CMS+frameworks; **trufflehog** verified secrets;
  **cloudbrute** public buckets; **email/job** intel.

Stop and emit the summary when the playbook is complete. Tool failure on one
step never blocks the rest.
