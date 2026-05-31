# Eval scenarios — golden fixtures

Each `*.scenario.json` here is a **recorded scan outcome** plus the **ground
truth** it should have recovered.  The runner in
`tests/eval/test_scenarios.py` rebuilds an `InformationStore` from `records`,
scores it against `ground_truth` with `fackel.eval.evaluate_store`, and asserts
the per-type and overall precision/recall/F1 stay at or above `thresholds`.

These are deterministic — **no LLM, no network** — so they form a stable
regression net: if extraction / normalization / dedup logic regresses, a
scenario's F1 drops below its floor and the test fails.

## Schema

```jsonc
{
  "name": "human label",                 // shown in the parametrized test id
  "target": "acme-corp.test",            // RFC 6761 / RFC 5737 reserved names only
  "description": "what this scenario exercises",
  "records": [                            // what the scan extracted
    { "type": "SUBDOMAIN", "value": "www.acme-corp.test", "tool": "subfinder_enum", "phase": "osint" }
  ],
  "ground_truth": {                       // canonical InformationType value -> expected values
    "SUBDOMAIN": ["www.acme-corp.test", "api.acme-corp.test"]
  },
  "thresholds": {                         // PRF floors (inclusive). Omit a key to skip it.
    "overall": { "recall": 0.8, "precision": 1.0, "f1": 0.85 },
    "per_type": {
      "SUBDOMAIN": { "recall": 0.8 }
    }
  }
}
```

Notes:
- `type` and `ground_truth` keys must be **canonical `InformationType` values**,
  which are UPPERCASE and not always the obvious word. Valid values:
  `DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `HISTORICAL_IP_ADDRESS`, `TLS_SAN_DOMAIN`,
  `OPEN_PORT`, `SERVICE_VERSION`, `IP_CLASSIFICATION`, `TECH_FINGERPRINT`,
  `EMAIL`, `PERSON`, `USERNAME`, `ORGANIZATION`, `SOCIAL_ACCOUNT`, `DOCUMENT`,
  `PHONE`, `SECURITY_VULNERABILITY`, `CREDENTIAL_LEAK`. Note there is no `PORT`
  (use `OPEN_PORT`), no `VULNERABILITY` (use `SECURITY_VULNERABILITY`), and no
  WHOIS type. The loader rejects unknown values loudly.
- The store dedups by fingerprint, so two tools reporting the same `value`
  collapse to one record — give distinct values when you want distinct records.
- Use only reserved test identifiers: `.test` / `.example` domains and
  `203.0.113.0/24` (TEST-NET-3) addresses, so fixtures never point at real hosts.
