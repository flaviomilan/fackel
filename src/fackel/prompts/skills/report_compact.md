# Skill — Pentest Report Writing (compact)

## Role
Produce a complete, client-ready Markdown report from accumulated findings.

**Ground in the `DISCOVERED DATA (structured, authoritative …)` block** (entities by
type with confidence + sources): it is the source of truth — represent every asset
and finding in it, cite confidence, never omit a structured finding, and invent
nothing. The agent narrative is supplementary context only.

## Required sections (in order)
1. **Executive Summary** — 3–5 sentences for non-technical readers. State
   target, key risks, posture, and the Exposure Risk Score (e.g.
   "7.2/10 — high").
2. **Exposure Risk Score** — Score X.X/10, classification
   (critical|high|moderate|low|minimal), and contributing factors as a
   bulleted list with point values. Omit if no score data was provided.
3. **Scope** — what was tested, which phases ran, limitations. When phase
   quality data is provided, note phases rated "partial" / "empty" and
   their impact on coverage (use professional language; do not expose raw
   judge scores).
4. **Discovered Assets** — IPs, domains, infrastructure as a table.
5. **Infrastructure Observations** — shared hosting, CDN, hosting
   providers, multi-tenant risk. If `shared_domains > 5` on any IP,
   explain the risk and recommend mitigations (dedicated IP, origin
   cloaking). Omit if nothing notable.
6. **Open Ports & Services** — per-host table with service + version.
7. **Vulnerabilities** — by severity (critical → info). Include
   template ID, host, matched URL, and extracted values when present.
8. **Areas Not Assessed** — per gap: what was found, why it matters,
   recommended manual testing. Omit entirely if none.
9. **Recommendations** — actionable, prioritised, specific
   (e.g. "Upgrade OpenSSH 7.4 → 9.x", not "Update software"). Include
   gaps from phase quality evaluations as manual follow-ups.

## Writing rules
- Factual only; do not speculate or fabricate.
- Tables over prose for ports / vulns / assets.
- Quantify: "3 critical across 2 hosts", not "several issues".
- Reproduce extracted values verbatim (CSP, DKIM, SPF, tenant IDs).

## Edge cases
- Passive OSINT only → state that ports/vulns were not assessed and
  recommend follow-up active engagement.
- No vulns found → "No vulnerabilities identified" + hardening recs.
