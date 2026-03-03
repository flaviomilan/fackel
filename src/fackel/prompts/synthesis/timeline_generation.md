# Synthesis — Geração de Timeline

## Objetivo

Construir uma timeline temporal dos achados e eventos, mostrando quando
cada componente da superfície de ataque foi first seen, last updated e
como a postura de segurança evoluiu.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `all_findings`       | `list[dict]` | Achados com timestamps                  |
| `tool_executions`    | `list[dict]` | Log de execuções de ferramentas         |
| `historical_data`    | `dict`       | Dados históricos (Wayback, CT, DNS)     |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `timeline`           | `list[dict]` | Eventos ordenados cronologicamente      |
| `first_seen`         | `dict`       | First seen por entidade/achado          |
| `changes_detected`   | `list[dict]` | Mudanças detectadas ao longo do tempo   |
| `temporal_patterns`  | `list[dict]` | Padrões temporais identificados         |

## Regras

1. **Fontes temporais**:
   - Timestamps de scan (mais confiável — agora).
   - CT log not_before/not_after (confiável para certificados).
   - Wayback Machine timestamps (confiável para conteúdo web).
   - Shodan/Censys last_seen (moderadamente confiável).
   - WHOIS creation/update dates (confiável para registration).
2. **Normalizar para UTC** — todos os timestamps em UTC ISO 8601.
3. **Distinguir first_seen from first_known** — first_seen é quando
   nossa ferramenta viu, first_known é o mais antigo de qualquer fonte.
4. **Mudanças são significativas** — mudança de IP, nova porta aberta,
   novo certificado, nova tecnologia.
5. **Timeline do assessment** — além da timeline do alvo, documentar
   quando cada ferramenta rodou e o que encontrou.

## Critérios de Qualidade

- Todos os eventos com timestamp preciso ou range estimado.
- Distinção entre "observado em" e "existia desde".
- Mudanças correlacionadas com eventos (novo deploy, migração).
- Timeline visual possível a partir dos dados.

## Template

```
TIMELINE
=========

| Timestamp           | Evento                         | Entidade    | Fonte        |
|---------------------|--------------------------------|-------------|-------------|
| 2025-01-15          | Domínio registrado             | example.com | WHOIS       |
| 2025-02-01          | Certificado emitido            | *.example.com| CT log     |
| 2025-02-20 14:30    | Scan: 5 portas abertas         | 203.0.113.10| nmap        |
| 2025-02-20 14:35    | WordPress 6.4 detectado        | example.com | whatweb      |
| 2025-02-20 14:45    | CVE-2024-1234 confirmado       | example.com | nuclei       |

Padrões temporais:
- [Certificado renovado recentemente — infraestrutura ativa]
- [Última atualização DNS há 6 meses — possível abandono]

Mudanças detectadas:
- [IP mudou de X para Y entre timestamp A e B]
```
