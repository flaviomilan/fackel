# Synthesis — Agrupamento de Entidades

## Objetivo

Agrupar achados por entidade lógica (host, serviço, organização, domínio)
para construir perfil completo de cada componente da superfície de ataque.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `all_findings`       | `list[dict]` | Todos achados validados                 |
| `dns_records`        | `dict`       | Mapeamento DNS                          |
| `ip_mapping`         | `dict`       | IP → hostnames                          |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `entity_profiles`    | `list[dict]` | Perfil completo por entidade            |
| `entity_graph`       | `dict`       | Relações entre entidades                |
| `orphan_findings`    | `list[dict]` | Achados não associados a entidade       |

## Regras

1. **Entidades primárias**: IP, hostname, domínio, organização, serviço.
2. **Regras de agrupamento**:
   - Mesmo IP → mesma entidade (mesmo que hostnames diferentes).
   - Mesmo CNAME chain → entidades relacionadas.
   - Mesmo registrante WHOIS → mesma organização.
   - Mesmo ASN → mesma infraestrutura (relacionados, não idênticos).
3. **Perfil mínimo por entidade**:
   - Identificadores (IP, hostname, domínio)
   - Portas/serviços
   - Tecnologias
   - Vulnerabilidades
   - Risk score agregado
4. **Não agregar excessivamente** — CDN IP com 100 sites não é uma entidade.
5. **Achados órfãos** são documentados, não descartados.

## Critérios de Qualidade

- Toda entidade com perfil completo.
- Relações entre entidades documentadas.
- Achados órfãos listados separadamente.
- Agrupamento consistente (mesmo critério para todos).

## Template

```
AGRUPAMENTO DE ENTIDADES
=========================

Entidade: [hostname/IP]
├── Identificadores: [IP, hostname, domínio]
├── Portas: [22, 80, 443]
├── Serviços: [ssh, http, https]
├── Tecnologias: [nginx 1.24, PHP 8.2, WordPress 6.4]
├── Vulnerabilidades: [CVE-2024-1234 (critical), ...]
├── OSINT: [breach data, WHOIS info]
├── Risk Score: [7.5/10]
└── Relações: [relacionado com entity-002 via CNAME]

Achados não associados: [lista]
```
