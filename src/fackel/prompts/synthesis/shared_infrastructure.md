# Synthesis — Infraestrutura Compartilhada

## Objetivo

Identificar componentes de infraestrutura compartilhados entre diferentes
entidades do alvo (shared hosting, CDN, DNS, mail servers) e avaliar
riscos de interdependência.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `entity_profiles`    | `list[dict]` | Perfis de entidades                     |
| `dns_records`        | `dict`       | Records DNS                             |
| `asn_data`           | `dict`       | Dados de ASN/BGP                        |
| `whois_data`         | `dict`       | Dados WHOIS                             |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `shared_components`      | `list[dict]` | Componentes compartilhados           |
| `dependency_risks`       | `list[dict]` | Riscos de dependência                |
| `single_points_of_failure`| `list[dict]`| SPOFs identificados                  |

## Regras

1. **Componentes a verificar**:
   - **IP sharing**: múltiplos hostnames no mesmo IP (shared hosting).
   - **CDN common**: todos os sites atrás do mesmo CDN (Cloudflare, AWS CF).
   - **DNS provider**: todos usando mesmo nameserver.
   - **Mail provider**: MX records apontando para mesmo provider.
   - **Certificate issuer**: mesmo CA para todos os certs.
2. **SPOF é risco alto** — componente único que, se comprometido, afeta
   toda a infraestrutura.
3. **CDN/WAF compartilhado** — bypass no CDN expõe todos os sites.
4. **DNS takeover risk** — se NS é terceirizado, avaliar risco de
   takeover.
5. **Documentar, não julgar** — infraestrutura compartilhada não é
   necessariamente ruim, mas é risco a documentar.

## Critérios de Qualidade

- Todos os componentes compartilhados identificados.
- SPOFs explicitamente marcados.
- Risco de cada compartilhamento avaliado.
- Distinção entre shared (risco) e redundant (mitigação).

## Template

```
INFRAESTRUTURA COMPARTILHADA
==============================

| Componente           | Tipo     | Entidades        | SPOF? | Risco    |
|----------------------|----------|------------------|-------|----------|
| 203.0.113.10         | IP       | site1, site2     | sim   | médio    |
| Cloudflare           | CDN/WAF  | todos (5 sites)  | sim   | alto     |
| ns1.registrar.com    | DNS      | todos (3 domínios)| sim  | alto     |
| Google Workspace     | Email    | todos             | não   | baixo    |

SPOFs identificados:
1. [Cloudflare] — bypass expõe origin servers de todos os sites
2. [DNS provider] — compromise permite redirect de todos os domínios

Riscos de dependência:
- [descrição do risco com impacto estimado]
```
