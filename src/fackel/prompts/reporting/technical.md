# Reporting — Relatório Técnico

## Objetivo

Gerar relatório técnico detalhado com todos os achados, evidências,
metodologia e dados brutos para audiência técnica (engenheiros de
segurança, DevOps, SRE).

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `validated_findings` | `list[dict]` | Achados validados com severidade        |
| `entity_profiles`    | `list[dict]` | Perfis de entidades                     |
| `attack_chains`      | `list[dict]` | Cadeias de ataque                       |
| `tool_executions`    | `list[dict]` | Log de ferramentas executadas           |
| `coverage`           | `dict`       | Análise de cobertura                    |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `technical_report`   | `string`     | Relatório técnico completo (Markdown)   |
| `findings_table`     | `list[dict]` | Tabela de achados estruturada           |
| `remediation_steps`  | `list[dict]` | Passos de remediação técnicos           |

## Regras

1. **Estrutura obrigatória**:
   - Executive Summary (mesmo em report técnico)
   - Scope & Methodology (ferramentas, datas, limitações)
   - Findings (ordenados: critical → info)
   - Attack Surface Map
   - Remediation Roadmap
   - Technical Appendix (raw data, commands)
2. **Cada finding deve incluir**:
   - Título descritivo
   - Severidade + CVSS (se aplicável)
   - Descrição técnica (o que foi encontrado)
   - Evidência (request/response, screenshot, output)
   - Impacto (o que atacante pode fazer)
   - Remediação (como corrigir, com código/config se possível)
   - Referências (CVE, CWE, OWASP)
3. **Evidência é obrigatória** — finding sem evidência não entra no report.
4. **Comandos reproduzíveis** — incluir commands que reproduzem o achado.
5. **Linguagem técnica precisa** — sem simplificação excessiva.

## Critérios de Qualidade

- Reprodutível: outro engenheiro consegue verificar cada finding.
- Completo: todos os achados validados presentes.
- Preciso: severidades consistentes, evidências verificáveis.
- Acionável: remediação com passos concretos.

## Template

```markdown
# Relatório Técnico de Assessment — ${target}

## 1. Resumo Executivo
[1 parágrafo: escopo, principais findings, risco geral]

## 2. Escopo e Metodologia
- **Alvo**: ${target}
- **Período**: ${start_date} — ${end_date}
- **Ferramentas**: [lista com versões]
- **Limitações**: [WAF, rate limits, scope constraints]

## 3. Findings

### 3.1 [CRITICAL] ${finding_title}
- **CVSS**: ${score} (${vector})
- **Descrição**: [descrição técnica detalhada]
- **Evidência**: 
  ```
  [request/response ou output]
  ```
- **Impacto**: [o que atacante consegue]
- **Remediação**: [como corrigir com instruções específicas]
- **Referências**: CVE-XXXX-XXXX, CWE-XXX

## 4. Mapa de Superfície de Ataque
[entidades, relações, portas, serviços]

## 5. Roadmap de Remediação
| Prioridade | Ação                | Esforço | Impacto |
|------------|---------------------|---------|---------|
| 1          | Patch CVE-XXXX      | baixo   | alto    |

## 6. Cobertura
[o que foi testado, o que não foi]

## 7. Apêndice Técnico
[raw data, full scan outputs, metodologia detalhada]
```
