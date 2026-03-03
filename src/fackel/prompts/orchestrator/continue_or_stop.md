# Orchestrator — Continue or Stop

## Objetivo

Decidir se o pipeline deve continuar executando ferramentas ou parar
porque cobertura suficiente foi alcançada, budget esgotou, ou
retornos são decrescentes.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `iteration`          | `int`        | Número da iteração atual                |
| `findings_count`     | `int`        | Total de achados coletados              |
| `new_findings_delta` | `int`        | Novos achados na última iteração        |
| `coverage`           | `dict`       | Cobertura por categoria                 |
| `budget_remaining`   | `dict`       | Budget restante                         |
| `unresolved_gaps`    | `list[dict]` | Lacunas ainda abertas                   |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `decision`           | `string`     | "continue" ou "stop"                    |
| `reason`             | `string`     | Justificativa da decisão                |
| `remaining_value`    | `float`      | Valor estimado de continuar (0-1)       |

## Regras

1. **Parar quando**:
   - 3 iterações sem novos achados significativos (retorno decrescente).
   - Budget esgotado (0 chamadas restantes).
   - Cobertura >= 90% em todas as categorias.
   - Todas as hipóteses testadas.
2. **Continuar quando**:
   - Vulns critical encontradas que requerem investigação.
   - Lacunas significativas em categorias importantes.
   - Novos alvos descobertos não investigados.
   - Budget disponível e ROI positivo.
3. **Nunca parar se**:
   - Vuln critical confirmada sem evidência completa.
   - Escopo principal não foi coberto minimamente.
4. **Nunca continuar se**:
   - Budget zerado.
   - Últimas 3 iterações sem delta > 0.
   - Alvo não responde / indisponível.

## Critérios de Qualidade

- Decisão binária clara (continue/stop).
- Razão concreta, não vaga.
- remaining_value reflete análise honesta.

## Template

```
DECISÃO: CONTINUE OR STOP
==========================

Métricas:
- Iteração: ${iteration}
- Achados totais: ${findings_count}
- Delta última iteração: ${new_findings_delta}
- Cobertura: ${coverage}
- Budget restante: ${budget_remaining}

Análise:
- Retorno decrescente? [sim/não — últimas 3 deltas]
- Lacunas críticas abertas? [lista]
- Budget permite mais uma iteração? [sim/não]

Decisão: [CONTINUE | STOP]
Razão: [justificativa concreta]
Valor de continuar: [0.0 - 1.0]
```
