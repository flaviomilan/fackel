# Tool — API Fuzzing & Directory Discovery

## Objetivo

Descobrir diretórios ocultos, arquivos sensíveis, endpoints de API
e virtual hosts via brute-force com wordlists.

## Ferramentas

| Ferramenta        | Propósito                                          |
|-------------------|----------------------------------------------------|
| `ffuf_scan`       | Fuzzing rápido de diretórios/arquivos/API          |
| `feroxbuster_scan`| Directory brute-force recursivo                    |

## Quando Usar Cada Ferramenta

- **`ffuf_scan` primeiro** quando o objetivo é:
  - API endpoint discovery (suporta FUZZ keyword posicional)
  - Testar múltiplos métodos HTTP (GET, POST, PUT, DELETE, OPTIONS)
  - Endpoints autenticados (suporta headers customizados)
  - Virtual host discovery (header `Host: FUZZ.example.com`)
- **`feroxbuster_scan` primeiro** quando o objetivo é:
  - Directory tree recursivo com profundidade (depth 1-4)
  - Content discovery geral (backup files, admin panels, configs)
  - Brute-force extenso com extensions automáticas
- **Fallback mútuo** — se um falhar (dependência, timeout, WAF), usar
  o outro imediatamente. São intercambiáveis para discovery básico.

## Regras de Uso

1. **ffuf para API endpoint discovery** — usar com wordlists de API:
   - `https://api.example.com/v1/FUZZ` para endpoints REST
   - `https://example.com/FUZZ` para diretórios
2. **Testar múltiplos métodos HTTP em APIs** — GET para leitura,
   POST/PUT para escrita, DELETE para remoção, OPTIONS para CORS.
   Status 405 (Method Not Allowed) confirma endpoint válido.
3. **Headers para endpoints autenticados** (somente `ffuf_scan`):
   - `Authorization: Bearer <token>` para APIs REST
   - `Cookie: session=<value>` para aplicações web
   - Testar endpoints autenticados quando tokens disponíveis.
4. **Virtual host discovery** com ffuf:
   - URL: `https://<IP>/` com header `Host: FUZZ.example.com`
   - Wordlist de subdomínios (não de diretórios)
   - Filtrar por `filter_size` — vhosts inexistentes retornam mesmo tamanho.
5. **Extensões relevantes** — `.php,.html,.js,.json,.xml,.txt,.bak,.conf`
   baseado na tecnologia detectada.
6. **Match codes seletivos** — default: 200,204,301,302,307,401,403,405.
   - 401/403 indicam recursos protegidos mas existentes.
   - 405 indica endpoint válido mas método errado.
7. **Filtragem de false positives** — workflow iterativo:
   - Scan inicial sem filtros de tamanho.
   - Se muitos resultados com mesmo tamanho/words → custom 404 page.
   - Re-scan com `filter_size` ou `filter_words` para excluir padrão.
   - Exemplo: 200 resultados todos com length 1234 → `filter_size: "1234"`.
8. **Threads adaptativas** — default 20 para targets normais.
   - Reduzir para 5-10 sob WAF ou rate limiting.
   - Aumentar até 50 apenas em targets robustos sem proteção.
9. **Correlacionar com tecnologia detectada** — WordPress → wp-admin,
   wp-content; Laravel → .env, artisan; etc.

## Limites de Escopo

- Somente hosts autorizados.
- Threads: default 20, máximo 50. Reduzir sob WAF.
- Wordlists padrão (SecLists common.txt ou dirb/common.txt).
- Não executar fuzzing recursivo sem justificativa.
- Respeitar rate limiting e WAF.

## Estratégia de Fallback

| Cenário                    | Ação                                       |
|----------------------------|--------------------------------------------|
| WAF bloqueando requests    | Reduzir threads para 5-10, documentar WAF  |
| Wordlist não encontrada    | Ambas usam wordlist bundled automaticamente|
| feroxbuster falhou         | Usar ffuf_scan como alternativa            |
| ffuf falhou                | Usar feroxbuster_scan como alternativa     |
| Muitos resultados (>500)   | Filtrar por status 200 ou filter_size      |
| Custom 404 detectado       | Re-scan com filter_size do tamanho padrão  |
| ffuf/feroxbuster timeout   | Reduzir wordlist ou extensões              |

> **IMPORTANTE**: ffuf e feroxbuster são complementares e intercambiáveis.
> Se um falhar (dependência, timeout, erro), use o outro imediatamente.
> Ambos agora incluem wordlist automática — não devem falhar por wordlist.

## Estrutura de Output

### ffuf_scan

```json
{
  "tool": "ffuf_scan",
  "target": "https://example.com/FUZZ",
  "status": "ok",
  "data": {
    "total": 2,
    "findings": [
      {
        "url": "https://example.com/admin",
        "input": "admin",
        "status": 200,
        "length": 1234,
        "words": 100,
        "lines": 50,
        "content_type": "text/html",
        "redirect_location": ""
      },
      {
        "url": "https://example.com/api",
        "input": "api",
        "status": 301,
        "length": 0,
        "words": 0,
        "lines": 0,
        "content_type": "",
        "redirect_location": "https://example.com/api/"
      }
    ]
  }
}
```

### feroxbuster_scan

```json
{
  "tool": "feroxbuster_scan",
  "target": "https://example.com",
  "status": "ok",
  "data": {
    "total": 2,
    "results": [
      {
        "url": "https://example.com/admin",
        "status": 200,
        "length": 1234,
        "mime": "text/html",
        "words": 100,
        "lines": 50
      },
      {
        "url": "https://example.com/.env",
        "status": 200,
        "length": 56,
        "mime": "text/plain",
        "words": 10,
        "lines": 5
      }
    ]
  }
}
```

### Classificação de Severidade

- **high**: admin panels, config files (.env, .htaccess), backup files (.sql, .bak)
- **medium**: diretórios ocultos, endpoints protegidos (401/403)
- **info**: recursos comuns, redirects
