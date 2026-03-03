# Tool — API Querying (OSINT Aggregators)

## Objetivo

Consultar APIs externas de inteligência para obter informações sobre IPs,
domínios, hashes e infraestrutura do alvo.

## Ferramentas

| Ferramenta              | Fonte                  | Dados Principais                            |
|-------------------------|------------------------|---------------------------------------------|
| `shodan_lookup`         | Shodan                 | Portas, banners, vulns, geolocalização      |
| `censys_lookup`         | Censys                 | Serviços, certificados, protocolos          |
| `fofa_search`           | FOFA                   | Assets web, fingerprinting de serviços      |
| `otx_passive_dns`       | AlienVault OTX         | Pulses, IOCs, malware, reputation           |
| `securitytrails_history` | SecurityTrails        | DNS history, subdomínios, WHOIS history     |
| `virustotal_subdomain_enum` | VirusTotal         | Detections, DNS, URLs, comunicações         |

## Regras de Uso

1. **Executar todas as APIs disponíveis em paralelo** — cada API tem
   dados únicos.
2. **API key necessária** — se key ausente, pular silenciosamente e
   documentar.
3. **Rate limits** — respeitar limites de cada API.  Shodan: 1/s,
   VirusTotal: 4/min (free), SecurityTrails: 50/day (free).
4. **Cruzamento obrigatório** — dados de múltiplas APIs devem ser
   cruzados para validação.
5. **Não confiar em fonte única** — dados de reputação (malicious/clean)
   requerem corroboração.

## Limites de Escopo

- Somente queries sobre alvos autorizados.
- Não seguir IOCs para pivoting sem autorização.
- Resultados de reputação são informativos, não conclusivos.

## Estratégia de Fallback

| Cenário                 | Ação                                        |
|-------------------------|---------------------------------------------|
| API key ausente         | Pular fonte, usar demais                    |
| Rate limit atingido     | Documentar, não retry                       |
| API indisponível        | Pular, documentar downtime                  |
| Dados conflitantes      | Reportar ambos com atribuição de fonte      |

## Estrutura de Output

```json
{
  "tool": "shodan_lookup",
  "target": "203.0.113.10",
  "data": {
    "ip": "203.0.113.10",
    "org": "Example Corp",
    "asn": "AS12345",
    "ports": [22, 80, 443, 8080],
    "vulns": ["CVE-2024-1234"],
    "country": "BR",
    "last_update": "2025-02-20"
  }
}
```

## Normalização

- IPs em formato IPv4/IPv6 padrão (sem zero-padding).
- ASNs com prefixo "AS" (ex: AS12345).
- CVEs no formato CVE-YYYY-NNNNN.
- Timestamps em ISO 8601 UTC.

## Anomalias

- **IP em múltiplas blocklists** → possível comprometimento ou reuso.
- **Portas incomuns abertas** (ex: 4444, 6666, 31337) → possível backdoor.
- **Histórico DNS mostrando mudanças frequentes** → possível compromisso
  ou fast-flux.
- **Certificados self-signed em produção** → configuração incorreta.
- **Dados de reputação conflitantes** → investigação adicional necessária.
