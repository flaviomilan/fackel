# Orchestrator — Ajuste de Estratégia

## Objetivo

Adaptar a estratégia do pipeline em tempo real baseado nos resultados
intermediários, ajustando agressividade, foco e técnicas.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `current_strategy`   | `dict`       | Estratégia atual (aggressividade, foco) |
| `findings_pattern`   | `dict`       | Padrões nos achados (tipo, severidade)  |
| `failures`           | `list[dict]` | Tools que falharam e razões             |
| `waf_detected`       | `bool`       | Se WAF foi detectado                    |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `adjusted_strategy`  | `dict`       | Nova estratégia                         |
| `changes`            | `list[dict]` | Mudanças aplicadas com razão            |
| `new_parameters`     | `dict`       | Parâmetros atualizados para tools       |

## Regras

1. **WAF detectado** → reduzir rate, usar User-Agent genérico, considerar
   bypasses conhecidos.
2. **Muitos timeouts** → reduzir paralelismo, aumentar timeouts individuais.
3. **Achados de alta severidade** → aprofundar nessa área (mais tools,
   mais params).
4. **Área sem achados após 3 tools** → reduzir foco, mover resources.
5. **Rate limiting detectado** → throttle automático + documentar.
6. **Ajustes são incrementais** — não mudar estratégia radicalmente.

## Critérios de Qualidade

- Cada ajuste com trigger claro e ação específica.
- Mudanças rastreáveis e reversíveis.
- Não over-react a eventos isolados.
- Manter consistência com objetivo geral do assessment.

## Template

```
AJUSTE DE ESTRATÉGIA
=====================

Triggers detectados:
- [lista de condições que ativaram ajuste]

Mudanças aplicadas:
1. [parâmetro] [valor antigo] → [valor novo] (razão: [trigger])
2. ...

Parâmetros atualizados:
- rate_limit: [novo valor]
- timeout: [novo valor]
- aggressiveness: [low | medium | high]
- focus_area: [área priorizada]
- tools_disabled: [tools temporariamente desabilitadas]
```
