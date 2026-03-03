# Tool — SQL Injection Scanning

## Objetivo

Detectar vulnerabilidades de SQL Injection em parâmetros de URL,
formulários POST, cookies e headers HTTP.

## Ferramentas

| Ferramenta    | Propósito                                              |
|---------------|--------------------------------------------------------|
| `sqlmap_scan` | Detecção automatizada de SQLi (boolean, time, error, UNION) |
| `nuclei_scan` | Templates específicos de SQLi com `-tags sqli`         |

## Regras de Uso

1. **sqlmap somente em endpoints com parâmetros** — URLs sem parâmetros
   não produzem resultados úteis.
2. **Modo batch obrigatório** — `--batch` é always-on para automação.
3. **Level e Risk conservadores**:
   - Level 1 (default): GET/POST params
   - Level 2: inclui Cookie header
   - Nunca usar level > 3 ou risk > 2 sem autorização explícita.
4. **nuclei como complemento** — usar `-tags sqli` para cobertura de
   CVEs conhecidas de SQLi em CMSs e frameworks.
5. **Confirmar findings** — SQLi requer evidência (payload + resposta).
6. **Não extrair dados** — apenas detectar, não usar `--dump`.

## Limites de Escopo

- Somente endpoints autorizados.
- NUNCA usar `--os-shell`, `--os-cmd`, `--dump` ou `--dump-all`.
- Rate limit: respeitar WAF/rate limiting do alvo.
- `--flush-session` para evitar cache de sessões anteriores.

## Estratégia de Fallback

| Cenário                    | Ação                                       |
|----------------------------|--------------------------------------------|
| WAF bloqueando payloads    | Documentar WAF, tentar `--tamper=space2comment` |
| sqlmap timeout             | Reduzir level, retry com timeout maior     |
| Sem parâmetros encontrados | Usar crawling + paramspider primeiro       |
| False positive             | Marcar como "needs manual verification"    |

## Normalização

- Technique padronizada: boolean-based blind, time-based blind,
  error-based, UNION query, stacked queries.
- Severity: critical (UNION/stacked), high (error-based/boolean), medium (time-based).
- Parameter name preservado.
