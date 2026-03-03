# Reporting — Resumo Estratégico

## Objetivo

Gerar análise estratégica da postura de segurança com foco em tendências,
maturidade e roadmap de melhorias de longo prazo.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `patterns`           | `list[dict]` | Padrões sistêmicos identificados        |
| `entity_profiles`    | `list[dict]` | Perfis de entidades                     |
| `coverage`           | `dict`       | Cobertura do assessment                 |
| `historical_data`    | `dict`       | Dados históricos (se disponíveis)       |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `strategic_summary`      | `string`     | Análise estratégica completa         |
| `maturity_assessment`    | `dict`       | Nível de maturidade por área         |
| `improvement_roadmap`    | `list[dict]` | Roadmap de melhorias (curto/médio/longo) |

## Regras

1. **Foco em padrões, não achados individuais** — o que os achados
   revelam sobre a postura geral.
2. **Maturidade por área**:
   - Patch Management: atualizado? processo existe?
   - Configuration Management: hardening? templates seguros?
   - Access Control: admin panels protegidos? MFA?
   - Monitoring: detecção de intrusão? logging?
   - Incident Response: preparação visível?
3. **Níveis de maturidade**: 1 (ad-hoc) → 5 (otimizado).
4. **Roadmap com 3 horizontes**:
   - Curto prazo (0-30 dias): quick wins, patches críticos.
   - Médio prazo (30-90 dias): hardening, processos.
   - Longo prazo (90-365 dias): maturidade, automação.
5. **Baseado em evidência** — cada assessment de maturidade com
   indicadores observados.

## Critérios de Qualidade

- Análise vai além dos achados individuais.
- Maturidade avaliada com indicadores concretos.
- Roadmap realista e priorizado.
- Não prescrever soluções específicas sem contexto organizacional.

## Template

```markdown
# Análise Estratégica de Segurança

## Postura Geral
[Parágrafo descrevendo a postura de segurança baseada nos padrões observados]

## Maturidade por Área

| Área                   | Nível (1-5) | Indicadores Observados              |
|------------------------|-------------|--------------------------------------|
| Patch Management       | 2           | Múltiplos serviços desatualizados    |
| Configuration          | 3           | Headers parciais, HTTPS ok           |
| Access Control         | 2           | Admin panels expostos                |
| Monitoring             | N/A         | Não observável externamente          |

## Forças Identificadas
- [Pontos positivos observados]

## Áreas de Melhoria
- [Fraquezas sistêmicas]

## Roadmap de Melhorias

### Curto Prazo (0-30 dias)
1. [Ação + justificativa]

### Médio Prazo (30-90 dias)
1. [Ação + justificativa]

### Longo Prazo (90-365 dias)
1. [Ação + justificativa]
```
