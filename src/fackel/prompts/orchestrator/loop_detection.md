# Orchestrator — Detecção de Loop

## Objetivo

Identificar e quebrar loops no pipeline onde as mesmas ferramentas são
chamadas repetidamente sem produzir novos resultados.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `tool_history`       | `list[dict]` | Histórico de chamadas (tool, target, timestamp) |
| `findings_per_call`  | `dict`       | Novos achados por chamada               |
| `current_iteration`  | `int`        | Iteração atual                          |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `loop_detected`      | `bool`       | Se loop foi detectado                   |
| `loop_type`          | `string`     | Tipo: exact_repeat, oscillation, drift  |
| `offending_tools`    | `list[str]`  | Tools envolvidas no loop                |
| `recommended_action` | `string`     | Ação corretiva                          |

## Regras

1. **Exact repeat** — mesma tool, mesmo target, mesmos params chamada
   2+ vezes → loop claro.
2. **Oscillation** — tool A → tool B → tool A → tool B sem novos
   achados → oscilação improdutiva.
3. **Drift** — target muda ligeiramente a cada iteração mas resultados
   não mudam → expansão sem valor.
4. **Tolerância**: 1 repeat é aceitável (retry legítimo), 2+ é loop.
5. **Ação padrão**: parar tools em loop, avançar para próxima fase.
6. **Não contar como loop**: mesma tool em targets diferentes (legítimo).

## Critérios de Qualidade

- Detecção precisa (sem falsos positivos em retry legítimo).
- Tipo de loop identificado corretamente.
- Ação corretiva específica e acionável.

## Template

```
DETECÇÃO DE LOOP
================

Analisar histórico de chamadas:

1. Agrupar por (tool, target):
   - Se count > 2 com mesmos achados → exact_repeat
   - Se alternância A→B→A→B com delta=0 → oscillation
   - Se target drift sem novos achados → drift

2. Se loop detectado:
   - Identificar tools offending
   - Recomendar: skip tools em loop, avançar fase
   - Ou: mudar estratégia (diferentes params/targets)

3. Se não detectado:
   - Confirmar que progresso está sendo feito
   - Reportar métricas de eficiência
```
