# Tool — DNS Resolution

## Objetivo

Resolver registros DNS de um domínio para obter endereços IP (A/AAAA)
e servir como ponto de partida para todas as fases subsequentes.

## Ferramenta

`dns_resolve`

## Regras de Uso

1. **Sempre primeiro** — DNS resolution é o primeiro passo para qualquer
   alvo do tipo domínio.
2. **Chamar uma vez por domínio** — não repetir a mesma resolução.
3. **Capturar A + AAAA** — registros IPv4 e IPv6.
4. **Domínios não-resolvíveis** — documentar como falha, não inventar.

## Limites de Escopo

- Somente domínios explicitamente autorizados.
- Não resolver domínios encontrados em dados de terceiros sem autorização.
- Não executar zone transfer (AXFR) — fora do escopo passivo.

## Estratégia de Fallback

- Se DNS público falha → documentar e usar dados de fontes OSINT (Shodan,
  Censys, SecurityTrails) como referência secundária.
- Se NXDOMAIN → domínio pode estar expirado ou typosquatted, documentar.

## Estrutura de Output

```json
{
  "tool": "dns_resolve",
  "target": "<domain>",
  "status": "success|error",
  "data": {
    "ipv4": ["<ip1>", "<ip2>"],
    "ipv6": ["<ip1>"],
    "cname": "<cname_if_any>"
  }
}
```

## Normalização

- IPs em formato canônico (sem leading zeros).
- IPv6 expandido completamente.
- CNAME chains resolvidas até o endereço final.

## Anomalias

- **CNAME para CDN** → indica proteção CDN (Cloudflare, AWS CloudFront).
  Documentar: o IP resolvido é do CDN, não do origin server.
- **Múltiplos IPs A** → possível round-robin ou anycast. Investigar todos.
- **Sem registro AAAA** → IPv6 não disponível. Nota informativa.
- **NXDOMAIN** → domínio não existe ou expirou.
