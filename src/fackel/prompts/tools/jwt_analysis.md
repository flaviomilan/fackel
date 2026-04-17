# Tool — JWT Analysis

## Purpose

Analyze JWT tokens to identify security weaknesses:
none algorithm, weak secrets, missing claims, expired tokens,
and dangerous headers (jku, jwk, kid injection).

## Tools

| Tool            | Purpose                                          |
|-----------------|------------------------------------------------------|
| `jwt_analyzer`  | JWT decoding and security analysis                |

## Usage Rules

1. **Use when JWT is detected** — in cookies, Authorization headers,
   API responses, or inline JavaScript.
2. **Passive analysis** — does not require additional requests to target.
3. **Check alg:none** — critical vulnerability that allows token forging.
4. **Check weak secrets** — brute-force against common wordlist.
5. **Required claims** — exp, iat, iss must be present.

## Finding Prioritization

| Finding                  | Severity   |
|--------------------------|------------|
| alg:none                 | critical   |
| Weak secret detected     | critical   |
| jku/jwk in header        | high       |
| kid path traversal       | high       |
| Missing exp claim        | high       |
| Expired token            | medium     |
| Symmetric alg (HS256)    | info       |
| Missing iat/iss          | low        |

## Scope Boundaries

- Only analysis of provided tokens — do not intercept traffic.
- Do not attempt to use modified tokens against target.
- Do not exfiltrate data via tokens.

## Correlation

- JWT with alg:none + API without rate limit → maximum risk.
- JWT with weak secret + missing exp → permanent access.
- JWT in JavaScript inline → combined with js_secret_scan.
