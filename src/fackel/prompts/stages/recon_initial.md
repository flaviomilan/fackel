# Stage — Recon Inicial

## Objetivo

Executar a fase de reconhecimento passivo para mapear a superfície externa
do alvo sem contato intrusivo.  Produzir uma visão inicial da infraestrutura
que alimente todas as fases seguintes.

## Inputs

| Campo              | Tipo     | Obrigatório | Descrição                               |
|--------------------|----------|-------------|-----------------------------------------|
| target             | string   | sim         | Domínio ou IP fornecido pelo operador   |
| target_type        | enum     | sim         | `domain` \| `ip`                        |
| user_context       | string   | não         | Contexto adicional do operador          |

## Outputs

| Campo                | Tipo       | Descrição                               |
|----------------------|------------|-----------------------------------------|
| discovered_ips       | list[str]  | IPv4 / IPv6 resolvidos                  |
| discovered_subdomains| list[str]  | Subdomínios únicos de múltiplas fontes  |
| registrar_info       | dict       | WHOIS — registrar, datas, nameservers   |
| ip_classifications   | list[dict] | ASN, org, anycast, ip_class por IP      |
| tech_fingerprints    | list[dict] | Headers, CDN, WAF, server por host      |
| tls_certificates     | list[dict] | Issuer, SANs, validade por host         |
| historical_dns       | list[dict] | A / MX / NS históricos (SecurityTrails) |

## Regras

1. **Passivo apenas** — nenhum port scan, nenhum brute-force, nenhum exploit.
   `httpx_scan` e `tlscert_lookup` são os únicos que tocam o alvo (HTTP e TLS).
2. **Paralelismo obrigatório** — agrupar chamadas independentes em batches.
3. **Deduplicação** — unificar subdomínios de subfinder, amass, crt.sh, etc.
4. **Falha de ferramenta não bloqueia** — se uma fonte falha, continuar com as demais.
5. **Se `user_context` fornecido** — priorizar aspectos mencionados (ex: "foco
   em vazamentos" → priorizar trufflehog + email analysis).

## Critérios de Qualidade

| Critério                          | Mínimo Esperado                       |
|-----------------------------------|---------------------------------------|
| Fontes de subdomínio consultadas  | ≥ 3 fontes distintas                  |
| IPs classificados                 | 100% dos IPs com ipinfo + bgp         |
| Fingerprint HTTP                  | httpx executado no domínio principal   |
| WHOIS obtido                      | Sim, ou falha documentada             |
| Certificado TLS inspecionado      | Sim, ou falha documentada             |

## Template

```text
Você está executando a fase de RECONHECIMENTO INICIAL para o alvo: ${target}

Objetivo: mapear a superfície externa do alvo usando técnicas passivas.

Restrições:
- Somente técnicas passivas + HTTP probing leve.
- Não expanda o escopo para alvos não autorizados.
- Documente cada ferramenta chamada e seu resultado.

${user_context ? "Contexto adicional do operador: " + user_context : ""}

Passos obrigatórios:
1. DNS + WHOIS (paralelo)
2. Enumeração de subdomínios — todas as fontes disponíveis (paralelo)
3. Enrichment por IP — ipinfo, bgp, reverse DNS (paralelo)
4. Shodan + Censys + FOFA (paralelo, por IP)
5. HTTP fingerprint + TLS + tech + histórico (paralelo)
6. URL discovery + secrets + cloud (paralelo)
7. Subdomain takeover check (após enum)

Formato de saída: resumo estruturado conforme especificação do agente OSINT.
```
