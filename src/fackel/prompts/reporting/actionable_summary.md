# Reporting — Resumo Acionável

## Objetivo

Gerar lista concisa e priorizada de ações que a equipe técnica deve
executar imediatamente, com instruções claras e estimativa de esforço.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `classified_findings`| `list[dict]` | Achados com severidade                  |
| `remediation_steps`  | `list[dict]` | Passos de remediação por achado         |
| `patterns`           | `list[dict]` | Padrões sistêmicos                      |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `action_items`       | `list[dict]` | Lista de ações priorizadas              |
| `quick_wins`         | `list[dict]` | Ações de alto impacto e baixo esforço   |
| `effort_estimate`    | `dict`       | Estimativa de esforço total             |

## Regras

1. **Priorização**: risco alto + esforço baixo primeiro (quick wins).
2. **Cada action item**:
   - Título conciso
   - O que fazer (instrução clara)
   - Por que (qual risco mitiga)
   - Como (passos ou comando)
   - Esforço estimado (horas/dias)
   - Achados endereçados (referências)
3. **Agrupar por tema** — se 5 achados se resolvem com "patch WordPress",
   é 1 action item, não 5.
4. **Máximo 15 action items** — mais que isso dilui atenção.
5. **Quick wins separados** — ações de <4h com impacto alto ficam em
   destaque.
6. **Instruções reproduzíveis** — "execute `apt update && apt upgrade`",
   não "atualize o sistema".

## Critérios de Qualidade

- Todo achado critical/high coberto por pelo menos 1 action item.
- Quick wins identificados e priorizados.
- Instruções específicas o suficiente para executar sem contexto adicional.
- Esforço estimado realista.

## Template

```markdown
# Ações Recomendadas

## Quick Wins (impacto alto, esforço < 4h)

### 1. [Título da ação]
- **Risco mitigado**: [descrição do risco]
- **Achados**: F-01, F-03, F-07
- **Instrução**: 
  ```
  [comando ou passo-a-passo]
  ```
- **Esforço**: ~2h
- **Impacto**: Resolve 3 findings (1 critical, 2 high)

## Ações Prioritárias

### 2. [Título da ação]
- **Risco mitigado**: [descrição]
- **Achados**: F-02, F-05
- **Instrução**: [passo-a-passo detalhado]
- **Esforço**: ~1 dia
- **Impacto**: [descrição]

## Ações de Médio Prazo
[ações que requerem planejamento mais longo]

## Estimativa Total
- Quick wins: ~8h
- Prioritárias: ~5 dias
- Médio prazo: ~15 dias
- **Total estimado**: ~4 semanas (1 engenheiro)
```
