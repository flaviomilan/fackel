# Stage — Relatório Final

## Objetivo

Compilar todos os achados validados, correlações, análise de risco e
recomendações em um relatório final estruturado e acionável.

## Inputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `validated_findings`     | `list[dict]` | Achados validados com confidence     |
| `correlations`           | `list[dict]` | Correlações confirmadas              |
| `risk_assessment`        | `dict`       | Análise de risco por componente      |
| `hypotheses_results`     | `list[dict]` | Hipóteses confirmadas/rejeitadas     |
| `coverage_analysis`      | `dict`       | Cobertura do assessment              |
| `${user_context}`        | `string`     | Contexto operacional (opcional)      |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `report`             | `dict`       | Relatório estruturado completo          |
| `executive_summary`  | `string`     | Resumo executivo (1 parágrafo)          |
| `findings_table`     | `list[dict]` | Tabela de achados por severidade        |
| `recommendations`    | `list[dict]` | Recomendações priorizadas               |
| `coverage_gaps`      | `list[str]`  | Áreas não cobertas pelo assessment      |

## Regras

1. **Estrutura obrigatória do relatório**:
   - Executive Summary
   - Scope & Methodology
   - Findings (por severidade: critical → info)
   - Risk Assessment
   - Recommendations
   - Coverage Analysis
   - Technical Details (appendix)
2. **Cada finding deve ter**: título, severidade, descrição, evidência,
   impacto, recomendação, referências (CVE/CWE).
3. **Severidade fundamentada** — não inflacionar. CVSS base score quando
   aplicável.
4. **Recomendações específicas** — "atualizar plugin X para versão Y",
   não "manter software atualizado".
5. **Áreas não cobertas** — documentar explicitamente o que não foi
   testado e por quê.
6. **Linguagem objetiva** — fatos, não opinião.  Evidência, não
   suposição.

## Critérios de Qualidade

- Todo finding com evidência verificável.
- Severidades consistentes (mesma classe de vuln = mesma severidade).
- Recomendações priorizadas por risco e esforço.
- Executive summary compreensível por não-técnicos.
- Nenhum dado inventado ou extrapolado.
- Cobertura documentada honestamente.

## Template

```
RELATÓRIO FINAL
===============

Seção 1 — Executive Summary
  Resumo em 1 parágrafo: escopo, achados principais, risco geral.

Seção 2 — Escopo e Metodologia
  Alvos, ferramentas, período, limitações.

Seção 3 — Achados
  Ordenados por severidade (critical > high > medium > low > info).
  Cada achado: título, severidade, descrição, evidência, impacto,
  remediação, CVE/CWE quando aplicável.

Seção 4 — Análise de Risco
  Risco por componente/host.  Mapa de calor de risco.

Seção 5 — Recomendações
  Priorizadas por: risco_alto + esforço_baixo primeiro.

Seção 6 — Cobertura
  O que foi testado, o que não foi, limitações encontradas.

Seção 7 — Apêndice Técnico
  Raw data, screenshots, evidências complementares.
```
