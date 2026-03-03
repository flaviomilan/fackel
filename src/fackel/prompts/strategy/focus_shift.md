# Strategy — Mudança de Foco

## Objetivo

Decidir quando e como mudar o foco de investigação durante o pipeline,
redirecionando resources de áreas improdutivas para áreas mais promissoras.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `area_productivity`  | `dict`       | Achados por unidade de esforço por área |
| `current_focus`      | `list[str]`  | Áreas em foco atualmente               |
| `unexplored_areas`   | `list[str]`  | Áreas ainda não investigadas            |
| `budget_remaining`   | `dict`       | Budget restante                         |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `new_focus`          | `list[str]`  | Novas áreas de foco                     |
| `defocused`          | `list[str]`  | Áreas removidas do foco com razão       |
| `focus_rationale`    | `string`     | Justificativa da mudança                |

## Regras

1. **Trigger para mudança de foco**:
   - Área com 3+ tools sem novos achados → reduzir foco.
   - Nova área com achado high/critical → imediatamente priorizar.
   - Budget < 30% → focar no mais impactante apenas.
2. **Não abandonar** áreas com findings parciais que requerem confirmação.
3. **Máximo 2 áreas de foco** simultaneamente — dispersão reduz qualidade.
4. **Mudança incremental** — não mudar tudo de uma vez.
5. **Documentar sempre** — cada mudança de foco registrada com razão.

## Critérios de Qualidade

- Decisão baseada em métricas de produtividade (achados/esforço).
- Áreas defocused com justificativa.
- Não reagir a eventos isolados (padrão requer 3+ data points).
- Equilíbrio entre exploração e exploração profunda.

## Template

```
MUDANÇA DE FOCO
================

Produtividade por área:
| Área          | Tools Usadas | Achados | Achados/Tool | Tendência |
|---------------|-------------|---------|-------------|-----------|
| Web App       | 5           | 12      | 2.4         | ↑         |
| Network       | 3           | 1       | 0.3         | ↓         |
| Cloud         | 1           | 3       | 3.0         | →         |
| OSINT         | 4           | 0       | 0.0         | ↓         |

Decisão:
- MANTER foco: Web App (produtividade alta)
- ADICIONAR foco: Cloud (alta produtividade inicial)
- REDUZIR foco: Network (baixa produtividade)
- REMOVER foco: OSINT (zero achados após 4 tools)

Razão: [justificativa geral da reconfiguração]
```
