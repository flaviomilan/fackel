# Tool — Subdomain Enumeration

## Objetivo

Descobrir subdomínios associados ao domínio alvo usando múltiplas fontes
passivas para maximizar cobertura.

## Ferramentas

| Ferramenta                | Fontes                                       |
|---------------------------|----------------------------------------------|
| `subfinder_enum`          | 40+ APIs passivas (Shodan, Censys, etc.)     |
| `amass_enum`              | CT logs, APIs, scraping, DNS brute (passivo)  |
| `crtsh_subdomain_enum`    | Certificate Transparency logs                |
| `dnsdumpster_lookup`      | DNS records + subdomínios via scraping       |
| `virustotal_subdomain_enum`| Passive DNS do VirusTotal (API key)         |

## Regras de Uso

1. **Chamar TODAS as fontes em paralelo** — cada fonte tem cobertura
   diferente.  Nunca depender de uma única fonte.
2. **Deduplicar resultados** — unificar subdomínios antes de reportar.
3. **subfinder + amass se complementam** — amass tem mais fontes,
   subfinder é mais rápido.  Executar ambos.
4. **Se uma fonte falha, continuar** — não bloquear por API key ausente
   ou rate limit.

## Limites de Escopo

- Somente subdomínios do domínio autorizado.
- Não expandir para domínios irmãos (ex: se alvo é `a.com`, não buscar
  `b.com` mesmo que pertença ao mesmo registrante).
- Wildcard DNS (*.domain.com) — documentar e filtrar dos resultados.

## Estratégia de Fallback

| Cenário                  | Ação                                         |
|--------------------------|----------------------------------------------|
| API key ausente          | Pular fonte, usar as demais                  |
| Rate limit               | Pular fonte, documentar                      |
| Timeout                  | Pular fonte, continuar com resultados parciais|
| Todas as fontes falham   | Documentar falha, usar crt.sh como mínimo     |

## Estrutura de Output

```json
{
  "subdomains": ["sub1.domain.com", "sub2.domain.com"],
  "sources": {"sub1.domain.com": ["subfinder", "crtsh"]},
  "total": 42,
  "source_counts": {"subfinder": 35, "crtsh": 28, "amass": 40}
}
```

## Normalização

- Lowercase.
- Remover trailing dots.
- Remover wildcards (*.domain.com).
- Remover duplicatas.

## Anomalias

- **Subdomínio sem resolução DNS** → possível dangling CNAME (subdomain
  takeover). Encaminhar para `subzy_check`.
- **Subdomínio com IP diferente dos principais** → infra separada, candidato
  a scan adicional.
- **Subdomínios com padrões** (dev-*, staging-*, test-*) → ambientes internos
  potencialmente expostos.  Alta prioridade.
- **Contagem muito alta (>500)** → possível wildcard DNS ou CDN com
  subdomínios dinâmicos.  Verificar antes de continuar.
