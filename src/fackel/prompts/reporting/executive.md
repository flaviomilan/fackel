# Reporting — Resumo Executivo

## Objetivo

Gerar resumo executivo conciso para audiência não-técnica (C-level,
board, stakeholders) focando em risco de negócio, não detalhes técnicos.

## Inputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `severity_distribution`  | `dict`       | Contagem por severidade              |
| `risk_assessment`        | `dict`       | Risco por componente                 |
| `attack_chains`          | `list[dict]` | Cadeias de ataque (simplificadas)    |
| `systemic_issues`        | `list[dict]` | Problemas sistêmicos                 |
| `${user_context}`        | `string`     | Contexto operacional (opcional)      |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `executive_summary`  | `string`     | Resumo executivo (1-2 páginas max)      |
| `risk_rating`        | `string`     | Rating geral: critical/high/medium/low  |
| `key_findings`       | `list[str]`  | Top 5 findings em linguagem de negócio  |
| `action_items`       | `list[str]`  | Ações imediatas recomendadas            |

## Regras

1. **Máximo 2 páginas** — brevidade é obrigatória.
2. **Linguagem de negócio** — não termos técnicos.
   - ❌ "CVE-2024-1234 RCE via deserialization"
   - ✅ "Vulnerabilidade crítica que permite controle total do servidor"
3. **Focar em impacto** — "dados de clientes podem ser acessados", não
   "SQL injection no parâmetro id".
4. **Risk rating geral** — uma palavra que resume a postura:
   - Critical: exploração ativa possível, dados em risco imediato.
   - High: vulnerabilidades sérias, remediação urgente.
   - Medium: problemas que requerem atenção planejada.
   - Low: postura razoável, melhorias incrementais.
5. **Top 5 findings** — os mais impactantes, em uma frase cada.
6. **Action items** — 3-5 ações concretas e priorizadas.

## Critérios de Qualidade

- Compreensível por não-técnicos.
- Sem jargão, siglas explicadas.
- Risk rating justificado.
- Action items acionáveis sem conhecimento técnico.
- Não alarmar desnecessariamente, não minimizar riscos reais.

## Template

```markdown
# Resumo Executivo — Assessment de Segurança

## Visão Geral
[1 parágrafo: o que foi avaliado, período, escopo]

## Rating de Risco Geral: ${RATING}
[1-2 frases justificando o rating]

## Principais Descobertas

1. **[Impacto em linguagem de negócio]** — Severidade: ${sev}
   O que significa: [consequência para o negócio]

2. **[Impacto em linguagem de negócio]** — Severidade: ${sev}
   O que significa: [consequência para o negócio]

[...até 5]

## Ações Recomendadas (por prioridade)

1. **[Ação]** — Prazo: imediato
2. **[Ação]** — Prazo: 30 dias
3. **[Ação]** — Prazo: 90 dias

## Próximos Passos
[1-2 frases sobre o que a organização deve fazer]
```
