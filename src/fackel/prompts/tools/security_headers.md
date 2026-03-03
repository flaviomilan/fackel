# Tool — Security Headers Audit

## Objetivo

Auditar headers de segurança HTTP para identificar configurações
ausentes ou fracas que expõem a aplicação a ataques.

## Ferramentas

| Ferramenta                | Propósito                                          |
|---------------------------|----------------------------------------------------|
| `security_headers_audit`  | Análise pura HTTP de headers de segurança          |

## Regras de Uso

1. **Executar em todos os hosts web descobertos** — é uma análise passiva
   que faz apenas um GET request.
2. **Priorizar findings** por severidade:
   - Missing CSP → high (permite XSS)
   - Missing HSTS → high (permite downgrade attack)
   - Missing X-Content-Type-Options → medium (MIME sniffing)
   - Missing X-Frame-Options → medium (clickjacking)
   - Weak CSP (unsafe-inline/unsafe-eval) → high
   - CORS wildcard com credentials → critical
3. **Correlacionar com outros findings** — se XSS foi detectado E CSP
   está ausente, escalar severidade do XSS.
4. **Information disclosure** — Server e X-Powered-By com versões
   facilitam exploração de CVEs específicas.

## Limites de Escopo

- Somente um GET request por host.
- Não testar variações (POST, OPTIONS) automaticamente.
- Respeitar rate limiting.

## Estratégia de Fallback

| Cenário                   | Ação                                       |
|---------------------------|--------------------------------------------|
| Host retorna 403/401      | Documentar e analisar headers disponíveis  |
| Redirect chain longa      | Analisar headers do destino final          |
| Timeout                   | Retry uma vez, depois documentar           |

## Normalização

- Header names em formato canônico (e.g. Content-Security-Policy).
- Severity padronizado: critical, high, medium, low, info.
- CSP directives listadas individualmente.
