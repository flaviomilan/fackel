# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Fackel is a **security tool** — we take vulnerabilities in the tool itself very
seriously.

**Do NOT open a public issue for security vulnerabilities.**

Instead, please report them via **GitHub private vulnerability reporting**:

1. Go to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the details — affected component, reproduction steps, potential impact.

We aim to acknowledge reports within **48 hours** and provide an initial
assessment within **5 business days**.

### What qualifies

- Command injection via tool inputs (bypass of `guard_target` / sanitizers)
- Arbitrary code execution through crafted scan targets
- Secrets leakage (API keys, tokens) in logs or reports
- Dependency vulnerabilities with a viable exploit path

### What does NOT qualify

- Missing features or documentation gaps
- Findings against targets you scan with Fackel (that's the tool working as intended)
- Denial of service against Fackel itself (it's a CLI tool, not a service)

## Responsible Disclosure

We follow coordinated disclosure. If you report a vulnerability:

1. We will work with you on a fix.
2. We will credit you in the release notes (unless you prefer anonymity).
3. We ask that you do **not** disclose publicly until a fix is released.

Thank you for helping keep Fackel secure.
