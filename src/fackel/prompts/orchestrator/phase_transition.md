# Orchestrator — Transição de Fase

## Objetivo

Decidir quando o pipeline deve transicionar entre fases (recon →
enumeration → scanning → validation → reporting), garantindo que
critérios de saída da fase atual foram satisfeitos.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `current_phase`      | `string`     | Fase atual do pipeline                  |
| `phase_objectives`   | `list[str]`  | Objetivos da fase atual                 |
| `objectives_met`     | `dict`       | Status de cada objetivo (bool + evidência)|
| `phase_duration`     | `int`        | Tempo na fase atual (iterações)         |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `transition`         | `bool`       | Se deve transicionar                    |
| `next_phase`         | `string`     | Próxima fase                            |
| `unmet_objectives`   | `list[str]`  | Objetivos não alcançados                |
| `carry_forward`      | `list[dict]` | Items para resolver na próxima fase      |
| `phase_summary`      | `string`     | Resumo da fase que está terminando      |

## Regras

1. **Critérios de saída por fase**:
   - **Recon**: domínios mapeados, IPs identificados, WHOIS coletado
   - **Enumeration**: subdomínios enumerados, portas escaneadas, serviços
     detectados
   - **Scanning**: vulns verificadas, tecnologias fingerprinted, web
     crawled
   - **Validation**: achados cruzados, falsos positivos filtrados,
     severidade atribuída
   - **Reporting**: relatório compilado, recomendações geradas
2. **Critério de 80%** — transicionar quando 80% dos objetivos da fase
   estão satisfeitos.
3. **Não transicionar se**:
   - Menos de 50% dos objetivos alcançados.
   - Vuln critical encontrada que requer investigação na fase atual.
4. **Timeout de fase** — se >5 iterações na mesma fase sem progresso,
   transicionar com carry_forward.
5. **Carry forward** — objetivos não alcançados são documentados e
   encaminhados como pendência.

## Critérios de Qualidade

- Decisão baseada em objetivos mensuráveis.
- Carry forward documentado explicitamente.
- Phase summary preciso e conciso.
- Transições não pulam fases (recon → scanning é proibido).

## Template

```
TRANSIÇÃO DE FASE
==================

Fase atual: ${current_phase}
Iterações: ${phase_duration}

Objetivos da fase:
| Objetivo                | Status | Evidência          |
|-------------------------|--------|--------------------|
| [objetivo 1]            | ✅/❌  | [referência]       |
| [objetivo 2]            | ✅/❌  | [referência]       |

Progresso: [X/Y objetivos] = [Z%]

Decisão: [TRANSICIONAR | CONTINUAR]
Próxima fase: [fase] (se transicionar)
Carry forward: [objetivos não alcançados]
Resumo: [o que foi alcançado nesta fase]
```
