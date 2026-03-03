# Tool — GraphQL Scanning

## Objetivo

Identificar endpoints GraphQL e testar vulnerabilidades comuns:
introspection habilitada, query complexity attacks, information disclosure.

## Ferramentas

| Ferramenta           | Propósito                                       |
|----------------------|-------------------------------------------------|
| `graphql_scan`       | Detecção de endpoint + introspection + vulns    |

## Regras de Uso

1. **Detectar endpoint primeiro** — testar paths comuns (/graphql,
   /api/graphql, /v1/graphql, /query).
2. **Introspection query** — se habilitada, extrair schema completo.
3. **Testar vulnerabilidades**:
   - Query complexity/depth limit
   - Batching attacks
   - Field suggestion (information disclosure)
   - Authorization bypass (acessar mutations sem auth)
4. **Preservar schema** — schema introspection é evidência valiosa.

## Limites de Escopo

- Somente endpoints GraphQL autorizados.
- Não executar mutations destrutivas.
- Queries de introspection são passivas (safe to run).

## Estratégia de Fallback

| Cenário                      | Ação                                    |
|------------------------------|-----------------------------------------|
| Introspection desabilitada   | Tentar field suggestion, documentar     |
| Endpoint não encontrado      | Testar paths alternativos               |
| Auth required                | Documentar, testar com/sem auth         |
| Rate limited                 | Reduzir query frequency                 |

## Estrutura de Output

```json
{
  "tool": "graphql_scan",
  "target": "https://example.com/graphql",
  "data": {
    "endpoint": "/graphql",
    "introspection_enabled": true,
    "types_count": 45,
    "queries_count": 12,
    "mutations_count": 8,
    "vulnerabilities": [
      {
        "type": "introspection_enabled",
        "severity": "medium",
        "evidence": "Full schema exposed"
      }
    ]
  }
}
```

## Normalização

- Endpoint como path relativo.
- Vulnerability types padronizados.
- Severity: critical, high, medium, low, info.

## Anomalias

- **Introspection em produção** → information disclosure (medium+).
- **Mutations sem auth** → potencial data manipulation (critical).
- **Sem depth limit** → DoS via nested queries (high).
- **Field suggestions revelam schema** → info disclosure mesmo sem introspection.
