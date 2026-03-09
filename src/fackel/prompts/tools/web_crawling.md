# Tool — Web Crawling & URL Discovery

## Objetivo

Descobrir URLs, endpoints, parâmetros e caminhos ocultos em aplicações
web do alvo para maximizar cobertura de superfície de ataque.

## Ferramentas

| Ferramenta          | Propósito                                        |
|---------------------|--------------------------------------------------|
| `katana_crawl`      | Crawler headless — SPA support, JS rendering     |
| `feroxbuster_scan`  | Directory/file brute-force                       |
| `gau_urls`          | URLs históricas (Wayback Machine, CT, Common Crawl)|
| `paramspider_crawl` | Descoberta de parâmetros em URLs                 |

## Regras de Uso

1. **GAU primeiro** — coletar URLs históricas (rápido, passivo).
2. **katana em paralelo com GAU** — crawling ativo com JS rendering.
3. **feroxbuster seletivo** — brute-force em hosts principais com
   wordlist direcionada (tecnologia detectada).
4. **paramspider nas URLs coletadas** — extrair parâmetros para XSS/SQLi.
5. **Deduplicar** — URLs de múltiplas fontes vão ter overlap significativo.

## Limites de Escopo

- Somente hosts no escopo autorizado.
- Profundidade máxima de crawling: 5 níveis.
- Não seguir links para terceiros (ads, analytics, CDNs).
- feroxbuster: wordlist de 5k max por host (não full dirbuster).
- Excluir extensões estáticas: .css, .png, .jpg, .gif, .svg, .woff.

## Estratégia de Fallback

| Cenário                     | Ação                                     |
|-----------------------------|------------------------------------------|
| WAF bloqueando crawler      | Reduzir rate, User-Agent genérico        |
| katana timeout em SPA       | Aumentar timeout JS, reduzir profundidade|
| feroxbuster muitos 403s     | Parar, WAF ativo — documentar            |
| GAU sem resultados          | Domínio novo — focar em crawling ativo   |
| Muitas URLs (>5000)         | Filtrar por unique paths, remover params |

## Estrutura de Output

```json
{
  "tool": "katana_crawl",
  "target": "https://example.com",
  "data": {
    "urls": [
      "https://example.com/api/v1/users",
      "https://example.com/admin/login",
      "https://example.com/graphql"
    ],
    "total_urls": 342,
    "unique_paths": 89,
    "forms_found": 5,
    "js_files": 23,
    "api_endpoints": 15
  }
}
```

## Normalização

- URLs normalizadas (encoding consistente).
- Remover fragmentos (#).
- Deduplicar por path (ignorar query params para contagem de paths).
- Classificar: page, api, form, asset, admin, auth.

## Anomalias

- **Endpoint /admin acessível** → verificar autenticação.
- **GraphQL endpoint** → testar introspection query.
- **APIs sem autenticação** → testar acesso direto.
- **URLs em Wayback Machine mas 404 agora** → possível conteúdo removido
  (info leak histórico).
- **Diretórios de backup** (.bak, .old, .tar.gz) → data exposure.
- **Parâmetros com padrão de ID sequencial** → IDOR potential.
