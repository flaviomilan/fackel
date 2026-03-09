# Tool — Content Fingerprinting

## Objetivo

Identificar tecnologias, frameworks, bibliotecas e componentes presentes
em aplicações web do alvo através de análise de conteúdo e headers.

## Ferramentas

| Ferramenta         | Propósito                                        |
|--------------------|--------------------------------------------------|
| `whatweb_scan`     | Fingerprint: CMS, frameworks, JS libs, analytics |
| `linkfinder_extract`| Extrair endpoints de arquivos JS                 |

## Regras de Uso

1. **whatweb em todo host web** — detectar CMS (WordPress, Joomla,
   Drupal), frameworks (React, Angular, Laravel) e versões.
2. **linkfinder em JS principais** — extrair APIs, endpoints internos,
   caminhos de administração.
3. **Executar após httpx** — usar URLs descobertas pelo probing.
4. **Preservar versões** — versão exata é crítica para busca de CVEs.

## Limites de Escopo

- Somente hosts dentro do escopo autorizado.
- Não executar testes ativos em endpoints descobertos (apenas discovery).
- JS de CDNs externas são informativos, não alvos.

## Estratégia de Fallback

| Cenário                     | Ação                                     |
|-----------------------------|------------------------------------------|
| WAF bloqueia whatweb        | Usar User-Agent genérico, documentar     |
| JS minificado               | linkfinder funciona mesmo minificado     |
| Host retorna 403            | Tentar paths alternativos (/robots.txt)  |
| Sem conteúdo web            | Documentar, não aplicar fingerprinting   |

## Estrutura de Output

```json
{
  "tool": "whatweb_scan",
  "target": "https://example.com",
  "data": {
    "technologies": [
      {"name": "WordPress", "version": "6.4.2", "confidence": 100},
      {"name": "PHP", "version": "8.2", "confidence": 90},
      {"name": "jQuery", "version": "3.7.1", "confidence": 100}
    ],
    "headers": {
      "x-powered-by": "PHP/8.2",
      "server": "nginx/1.24"
    }
  }
}
```

## Normalização

- Nomes de tecnologias padronizados (WordPress, não wordpress ou WP).
- Versões em semver quando possível.
- Confidence score preservado (0-100).

## Anomalias

- **CMS desatualizado** → verificar CVEs conhecidos imediatamente.
- **jQuery <3.5** → XSS via $.htmlPrefilter (CVE-2020-11022).
- **Endpoints de admin expostos** (/wp-admin, /administrator) → superfície
  de ataque crítica.
- **API keys em JS** → secret scanning imediato.
- **Headers de debug ativos** (X-Debug-Token, X-Powered-By com versão) →
  information disclosure.
