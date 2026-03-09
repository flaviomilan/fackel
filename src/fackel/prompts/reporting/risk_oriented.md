# Reporting — Relatório Orientado a Risco

## Objetivo

Gerar relatório focado em análise de risco, priorizando achados por
probabilidade de exploração × impacto ao negócio, com mapa de calor
de risco e cenários de ameaça.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `classified_findings`| `list[dict]` | Achados com severidade                  |
| `attack_chains`      | `list[dict]` | Cadeias de ataque                       |
| `entity_profiles`    | `list[dict]` | Perfis de entidades                     |
| `target_context`     | `dict`       | Contexto do alvo (indústria, dados)     |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `risk_report`        | `string`     | Relatório de risco (Markdown)           |
| `risk_matrix`        | `dict`       | Matriz probabilidade × impacto         |
| `threat_scenarios`   | `list[dict]` | Cenários de ameaça realistas            |
| `residual_risks`     | `list[dict]` | Riscos residuais após remediação        |

## Regras

1. **Matriz de risco 5×5**:
   - Probabilidade: muito baixa (1), baixa (2), média (3), alta (4), muito alta (5)
   - Impacto: insignificante (1), menor (2), moderado (3), maior (4), catastrófico (5)
   - Score = probabilidade × impacto
2. **Cenários de ameaça**:
   - Cada cenário com: ator, motivação, vetor, impacto, probabilidade.
   - Baseados em attack chains reais.
   - Máximo 5 cenários, priorizados por score.
3. **Contexto de negócio** — impacto considera tipo de dados (PII, financeiro),
   regulação (LGPD, PCI DSS), reputação.
4. **Risco residual** — após remediação, qual risco permanece?
5. **Não inventar cenários** — cada cenário baseado em evidência concreta.

## Critérios de Qualidade

- Matriz de risco com todos os achados plotados.
- Cenários baseados em evidence, não ficção.
- Impacto contextualizado ao negócio do alvo.
- Risco residual honesto (nem tudo se resolve).

## Template

```markdown
# Relatório de Análise de Risco

## Matriz de Risco
|              | Impacto 1 | Impacto 2 | Impacto 3 | Impacto 4 | Impacto 5 |
|--------------|-----------|-----------|-----------|-----------|-----------|
| Prob. 5      |           |           |           |           | [F-01]    |
| Prob. 4      |           |           | [F-05]    | [F-02]    |           |
| Prob. 3      |           | [F-08]    |           |           |           |
| Prob. 2      | [F-12]    |           |           |           |           |
| Prob. 1      |           |           |           |           |           |

## Cenários de Ameaça

### Cenário 1: ${nome}
- **Ator**: [tipo de atacante]
- **Motivação**: [financeira, hacktivismo, espionagem]
- **Vetor**: [descrição baseada em attack chain]
- **Impacto**: [consequência para o negócio]
- **Probabilidade**: [justificativa]
- **Score de Risco**: [probabilidade × impacto]

## Riscos Residuais
[Riscos que permanecem mesmo após remediação completa]
```
