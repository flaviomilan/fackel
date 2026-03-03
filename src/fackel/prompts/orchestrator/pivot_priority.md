# Orchestrator — Prioridade de Pivôs

## Objetivo

Priorizar alvos e linhas de investigação descobertos durante o pipeline,
decidindo onde investir resources limitadas para máximo impacto.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `discovered_targets` | `list[dict]` | Alvos descobertos durante o pipeline    |
| `existing_findings`  | `list[dict]` | Achados já coletados por alvo           |
| `risk_indicators`    | `dict`       | Indicadores de risco por alvo           |
| `budget_remaining`   | `dict`       | Resources restantes                     |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `priority_queue`     | `list[dict]` | Alvos ordenados por prioridade          |
| `investigate`        | `list[str]`  | Alvos que devem ser investigados        |
| `defer`              | `list[str]`  | Alvos adiados com razão                 |
| `discard`            | `list[str]`  | Alvos descartados com razão             |

## Regras

1. **Critérios de priorização** (peso decrescente):
   - Vulnerabilidade conhecida confirmada → prioridade máxima
   - Serviço desatualizado em porta exposta → alta
   - Subdomínio com padrão dev/staging/test → alta
   - Novo IP com múltiplas portas abertas → média
   - Domínio com apenas hosting padrão → baixa
2. **Budget-aware** — se budget < 20%, somente prioridade máxima e alta.
3. **Não pivotar excessivamente** — máximo 3 novos alvos por iteração.
4. **Pivôs devem ter razão** — "é novo" não é razão suficiente.
   Precisa de indicador de risco.
5. **Manter foco** — não abandonar alvos com findings parciais para
   investigar novos alvos.

## Critérios de Qualidade

- Cada alvo na priority_queue com score e justificativa.
- Descartados com razão clara.
- Equilíbrio entre exploração e profundidade.
- Budget awareness explícita na decisão.

## Template

```
PRIORIDADE DE PIVÔS
====================

1. Para cada alvo descoberto, calcular score:
   score = vulns_known(×3) + services_exposed(×2) + risk_indicators(×1)

2. Classificar:
   - INVESTIGATE: score >= 6 AND budget permite
   - DEFER: score 3-5 OR budget insuficiente
   - DISCARD: score < 3 OR out-of-scope

3. Limitar a top-3 por iteração.

4. Documentar decisão com:
   - Alvo
   - Score
   - Indicadores usados
   - Decisão + razão
```
