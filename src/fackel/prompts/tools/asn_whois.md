# Tool — ASN & WHOIS

## Objetivo

Mapear a infraestrutura de rede do alvo: blocos de IP, ASN ownership,
registrante WHOIS, nameservers e relacionamentos organizacionais.

## Ferramentas

| Ferramenta          | Propósito                                        |
|---------------------|--------------------------------------------------|
| `ipinfo_lookup`     | Geolocalização, ASN, org para IP                 |
| `bgp_lookup`        | Prefixos BGP, peers, ASN ownership               |
| `whois_lookup`      | Registrante, datas, nameservers do domínio       |

## Regras de Uso

1. **WHOIS em todo domínio raiz** — registrante e nameservers são
   essenciais para mapeamento organizacional.
2. **ipinfo em IPs principais** — geolocalização e ASN para entender
   distribuição geográfica.
3. **bgpview para ASN** — quando um ASN é identificado, buscar todos os
   prefixos para mapear range completo.
4. **Cruzar registrante** — mesmo registrante pode indicar outros
   domínios da organização.

## Limites de Escopo

- Somente IPs e domínios autorizados.
- Não expandir automaticamente para todos os IPs de um /16.
- ASN adjacentes são informativos, não alvos.

## Estratégia de Fallback

| Cenário                  | Ação                                        |
|--------------------------|---------------------------------------------|
| WHOIS privacy/proxy      | Documentar privacidade, buscar org via ASN  |
| Rate limit WHOIS         | Esperar 60s, retry                          |
| IP sem ASN (RFC 1918)    | Documentar como IP privado, não consultar   |
| bgpview indisponível     | Usar ipinfo como fallback para ASN          |

## Estrutura de Output

```json
{
  "tool": "whois_lookup",
  "target": "example.com",
  "data": {
    "registrant": "Example Corp",
    "registrar": "NameCheap",
    "creation_date": "2010-05-15",
    "expiration_date": "2026-05-15",
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "dnssec": true,
    "privacy_protected": false
  }
}
```

## Normalização

- Datas em ISO 8601.
- ASNs com prefixo "AS" (ex: AS13335).
- Nameservers em lowercase.
- CIDR notation para ranges de IP.

## Anomalias

- **Domínio próximo de expiração** → risco de domain hijacking.
- **WHOIS recém-alterado** → possível transferência ou compromisso.
- **Nameservers inconsistentes com CDN** → configuração mista.
- **ASN com poucos prefixos** → organização pequena, mais vulnerável.
- **Registrante diferente do esperado** → possível shadow IT ou aquisição.
