# Stage — Análise Estratégica

## Objetivo

Avaliar a postura de segurança do alvo como um todo, sintetizando os
achados em uma narrativa estratégica que conecte vulnerabilidades
individuais a riscos de negócio.

## Inputs

| Campo               | Tipo  | Obrigatório | Descrição                          |
|---------------------|-------|-------------|------------------------------------|
| consolidated_report | dict  | sim         | Inventário final consolidado       |
| risk_score          | dict  | sim         | Score e fatores de risco           |
| unassessed_areas    | list  | sim         | Lacunas de cobertura               |
| target_context      | dict  | sim         | Tipo de alvo, setor, tamanho       |

## Outputs

| Campo               | Tipo    | Descrição                              |
|---------------------|---------|----------------------------------------|
| strategic_assessment| string  | Avaliação narrativa da postura         |
| attack_paths        | list    | Cadeias de ataque possíveis            |
| priority_actions    | list    | Ações recomendadas ordenadas por ROI   |
| residual_risks      | list    | Riscos que permanecem após mitigação   |

## Regras

1. **Conectar técnico ao negócio** — "MySQL 8.0 exposto na porta 3306"
   deve ser contextualizado como "acesso direto ao banco de dados sem
   camada de aplicação intermediária".
2. **Attack paths** — quando múltiplos achados se combinam para criar
   um cenário de ataque, documentar a cadeia completa.
3. **Não especular** — se não há evidência de exploitability, dizer
   "potencialmente explorável" com caveats explícitos.
4. **Priorizar por impacto** — ações de mitigação ordenadas pelo
   impacto na redução de risco, não pela facilidade de implementação.
5. **Residual risks** — sempre listar o que permanece mesmo após
   implementar todas as recomendações.

## Critérios de Qualidade

| Critério                        | Esperado                              |
|---------------------------------|---------------------------------------|
| Cada attack path com evidência  | Achados concretos em cada elo         |
| Separation of concerns          | Fato / inferência / recomendação      |
| Priorização justificada         | Critério explícito                    |
| Linguagem para stakeholders     | Acessível a não-técnicos              |

## Template

```text
Fase de ANÁLISE ESTRATÉGICA para: ${target}

Risk score: ${risk_score}/10 (${exposure_type})
Vulnerabilidades: ${vuln_count} (critical: ${critical_count}, high: ${high_count})
Lacunas: ${gaps_count}

Análise:

1. Postura geral de segurança:
   - Superfície de ataque: ${surface_assessment}
   - Proteções observadas: ${protections}
   - Lacunas críticas: ${critical_gaps}

2. Cadeias de ataque possíveis:
   Para cada combinação de achados que forma um attack path:
   - Passo 1: achado A (ferramenta, evidência)
   - Passo 2: achado B que amplifica ou depende de A
   - Impacto potencial: consequência de negócio

3. Ações prioritárias (ordenadas por redução de risco):
   Para cada recomendação:
   - O quê: ação específica
   - Por quê: qual risco mitiga
   - Esforço: alto/médio/baixo

4. Riscos residuais:
   O que permanece mesmo com todas as recomendações implementadas.

Formato: narrativa estratégica com evidências citadas.
```
