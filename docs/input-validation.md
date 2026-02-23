# Input Validation

Fackel enforces **code-level input validation** on every tool that accepts a
target parameter. This is a critical safety layer — LLMs can and do pass
unexpected input types (IPs to domain-only tools, shell metacharacters in
arguments, URLs where bare hosts are expected).

Prompt-level instructions ("do NOT pass IPs") are insufficient because models
ignore them under pressure. `guard_target()` enforces constraints in code,
returning structured error messages that the LLM sees and can self-correct from.

---

## Table of contents

- [Design rationale](#design-rationale)
- [TargetType enum](#targettype-enum)
- [guard_target function](#guard_target-function)
- [Usage pattern](#usage-pattern)
- [Validation flow](#validation-flow)
- [Shell metacharacter blocking](#shell-metacharacter-blocking)
- [Per-tool target types](#per-tool-target-types)
- [Error format](#error-format)
- [Adding validation to a new tool](#adding-validation-to-a-new-tool)

---

## Design rationale

### Why code-level validation?

During real scans, the following was observed:

1. **Nuclei called with raw IPs** — Nuclei templates rely on DNS/SSL/SNI. Bare-IP
   scans behind CDN/proxy return nothing useful. Despite the prompt saying "do NOT
   run nuclei on raw IPs", the LLM did it anyway.

2. **Domain-only tools receiving URLs** — Tools like `whois_lookup` got passed
   `https://example.com` instead of `example.com`.

3. **Shell metacharacters in inputs** — Since most tools execute subprocesses,
   unvalidated inputs could lead to command injection.

The solution: every tool validates its input **at the function level** before any
processing happens. Invalid inputs return a clean error dict that the LLM sees in
the observation, learns from, and retries correctly.

### Design decisions

| Decision | Rationale |
|----------|-----------|
| Return `(value, error)` tuple, not exception | Compatible with LangChain tool error propagation — the LLM sees the error as a tool result |
| Shell metacharacter regex on all types | Security hardening — even if a domain looks valid, `example.com; rm -rf /` must be rejected |
| `_extract_host()` strips URL scheme | Tools that accept HOST may receive `https://example.com` — we extract the bare hostname before validation |
| `HOST_OR_URL` falls through to `HOST` validation for bare inputs | Avoids duplicating validation logic |
| Lazy import of `format_tool_output` | Prevents circular import between `validators.py` and `utils.py` |

---

## TargetType enum

```python
class TargetType(Enum):
    DOMAIN = "domain"           # Valid domain name only
    IP = "ip"                   # Valid IPv4/IPv6 address only
    HOST = "host"               # Domain OR IP
    URL = "url"                 # Requires http:// or https:// scheme
    HOST_OR_URL = "host_or_url" # Domain, IP, or full URL
```

### What each type accepts and rejects

| Type | Accepts | Rejects |
|------|---------|---------|
| `DOMAIN` | `example.com`, `sub.example.com` | `1.2.3.4`, `https://example.com`, `::1` |
| `IP` | `1.2.3.4`, `::1`, `2606:4700::1` | `example.com`, `https://1.2.3.4` |
| `HOST` | `example.com`, `1.2.3.4`, `::1` | `https://example.com` |
| `URL` | `https://example.com`, `http://1.2.3.4:8080/path` | `example.com`, `1.2.3.4` |
| `HOST_OR_URL` | `example.com`, `1.2.3.4`, `https://example.com/path` | *(nothing — most permissive for targets)* |

**All types reject** shell metacharacters and empty/whitespace-only inputs.

---

## guard_target function

```python
def guard_target(
    value: str,
    tool_name: str,
    accept: TargetType,
) -> tuple[str, dict | None]:
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `value` | `str` | Raw input from the LLM |
| `tool_name` | `str` | Tool name (used in error messages) |
| `accept` | `TargetType` | What kind of target this tool accepts |

### Return value

| Case | Returns | Action |
|------|---------|--------|
| Valid input | `(cleaned_value, None)` | Use `cleaned_value` going forward |
| Invalid input | `("", error_dict)` | Tool should `return error_dict` immediately |

The `cleaned_value` is stripped of whitespace. For `HOST_OR_URL` and `URL`
types, the full URL is preserved. For `HOST`, `DOMAIN`, and `IP`, only the bare
hostname/IP is returned (URL scheme and path are stripped).

---

## Usage pattern

Every tool that accepts a target uses this 3-line pattern at the top of its body:

```python
@tool(args_schema=MyInput)
def my_tool(target: str) -> dict:
    """My tool docstring — LLM reads this."""
    target, err = guard_target(target, "my_tool", TargetType.DOMAIN)
    if err:
        return err

    # ... proceed safely with validated 'target' ...
```

This is uniform across all 17 target-accepting tools.

---

## Validation flow

```
                    ┌─────────────┐
                    │ guard_target │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Empty input? │──Yes──▶ error: "target is empty"
                    └──────┬──────┘
                           │ No
                    ┌──────▼──────────┐
                    │ TargetType.URL? │──Yes──▶ Check scheme (http/https)
                    └──────┬──────────┘        Check hostname exists
                           │ No                Check shell metacharacters
                    ┌──────▼────────────────┐  Return full URL
                    │ TargetType.HOST_OR_URL │
                    │ with URL scheme?       │──Yes──▶ Check hostname
                    └──────┬────────────────┘         Check shell meta
                           │ No                       Return full URL
                    ┌──────▼───────────┐
                    │ _extract_host()  │  ← Strip scheme/path
                    └──────┬───────────┘
                           │
                    ┌──────▼──────────────┐
                    │ Shell metacharacters?│──Yes──▶ error: "forbidden characters"
                    └──────┬──────────────┘
                           │ No
                    ┌──────▼──────┐
                    │ Type check  │
                    │ DOMAIN/IP/  │──▶ Validate per type
                    │ HOST        │    Return cleaned value
                    └─────────────┘
```

---

## Shell metacharacter blocking

The regex blocks any of these characters from reaching subprocess arguments:

```
; & | ` $ ( ) { } ! [ ] < > ' " \ \n \r
```

Pattern: `[;&|` `` ` `` `$(){}!\[\]<>'\"\\\n\r]`

This applies to **all** target types, not just DOMAIN. Even IP addresses are
checked — a value like `1.2.3.4; rm -rf /` is rejected.

The check is applied to the **hostname portion only** (i.e. after stripping URL
scheme and path for URL/HOST_OR_URL types). This ensures `https://example.com/path?q=x&y=z`
passes validation — the `&` in the URL query is not part of the hostname.

---

## Per-tool target types

### DOMAIN (IPs and URLs rejected)

| Tool | Rationale |
|------|-----------|
| `whois_lookup` | WHOIS only works on domain names |
| `dnsdumpster_lookup` | DNSDumpster API expects root domains |
| `virustotal_subdomain_enum` | VT subdomain API expects root domains |
| `crtsh_subdomain_enum` | CT log search by domain |
| `subfinder_enum` | Subfinder expects domain input |
| `nuclei_scan` | Templates rely on DNS/SSL/SNI — bare IPs return nothing useful behind CDN |

### IP (domains and URLs rejected)

| Tool | Rationale |
|------|-----------|
| `reverse_dns_lookup` | PTR lookups require IP addresses |

### HOST (domain or IP, URLs rejected)

| Tool | Rationale |
|------|-----------|
| `dns_resolve` | Resolves domains to IPs, or validates IPs |
| `naabu_scan` | Port scanner accepts host |
| `nmap_port_scan` | Port scanner accepts host |
| `censys_lookup` | Censys accepts both |
| `testssl_scan` | TLS scan accepts host or host:port |

### HOST_OR_URL (most permissive)

| Tool | Rationale |
|------|-----------|
| `httpx_scan` | Probes HTTP on domain, IP, or specific URL |
| `wafw00f_detect` | WAF detection on domain or URL |
| `feroxbuster_scan` | Directory discovery — auto-adds `https://` if bare host |
| `katana_crawl` | Web crawler — auto-adds `https://` if bare host |

### URL (requires `http://` or `https://` scheme)

| Tool | Rationale |
|------|-----------|
| `graphql_scan` | Tests specific GraphQL endpoint URL |
| `extract_webpage_content` | Fetches specific page content |

---

## Error format

When validation fails, `guard_target()` returns a standard error dict via
`format_tool_output()`:

```python
{
    "tool": "nuclei_scan",
    "target": "1.2.3.4",
    "status": "error",
    "data": None,
    "error": "nuclei_scan requires a domain name, not an IP address. Use the domain or subdomain instead of 1.2.3.4."
}
```

The LLM sees this as the tool's observation, reads the error message, and
typically retries with the correct input type.

### Error messages

| Condition | Message |
|-----------|---------|
| Empty input | `target is empty` |
| Shell metacharacters | `target contains forbidden characters: '{value}'` |
| IP given to DOMAIN tool | `{tool} requires a domain name, not an IP address. Use the domain or subdomain instead of {ip}.` |
| Domain given to IP tool | `{tool} requires an IP address, got: '{value}'` |
| Invalid host | `invalid host (not a valid IP or domain): '{value}'` |
| Bare domain given to URL tool | `expected a full URL (http/https), got: {value}` |
| URL with no hostname | `URL has no hostname: {value}` |
| Invalid domain format | `invalid domain name: '{value}'` |

---

## Adding validation to a new tool

When creating a new tool, add validation in 3 steps:

### 1. Choose the appropriate `TargetType`

| If your tool... | Use |
|-----------------|-----|
| Only works with domain names | `TargetType.DOMAIN` |
| Only works with IP addresses | `TargetType.IP` |
| Works with domain or IP | `TargetType.HOST` |
| Needs a full URL with scheme | `TargetType.URL` |
| Works with any target format | `TargetType.HOST_OR_URL` |

### 2. Import and call `guard_target`

```python
from .validators import TargetType, guard_target

@tool(args_schema=MyInput)
def my_tool(target: str) -> dict:
    """Docstring for the LLM."""
    target, err = guard_target(target, "my_tool", TargetType.DOMAIN)
    if err:
        return err
    # ... safe to proceed
```

### 3. For HOST_OR_URL tools that need a URL

If your tool wraps a binary that requires a URL, add scheme auto-prepending
after the guard:

```python
target, err = guard_target(target, "my_tool", TargetType.HOST_OR_URL)
if err:
    return err

if not target.startswith(("http://", "https://")):
    target = f"https://{target}"
```

This is the pattern used by `feroxbuster_scan`, `katana_crawl`, and
`wafw00f_detect`.
