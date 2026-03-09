# Stage — Identificação de Lacunas

## Objetivo

Determinar quais áreas da superfície de ataque do alvo NÃO foram
adequadamente analisadas — tecnologias detectadas sem ferramenta
especializada, hosts não escaneados, vetores não explorados.

## Inputs

| Campo              | Tipo  | Obrigatório | Descrição                          |
|--------------------|-------|-------------|------------------------------------|
| tech_stack         | list  | sim         | Tecnologias detectadas             |
| tools_executed     | list  | sim         | Ferramentas que foram executadas   |
| scan_coverage      | dict  | sim         | Hosts/IPs escaneados vs total      |
| phase_evaluations  | list  | sim         | Avaliações de qualidade por fase   |

## Outputs

| Campo               | Tipo  | Descrição                                |
|---------------------|-------|------------------------------------------|
| unassessed_areas    | list  | Tecnologias/superfícies não avaliadas    |
| partial_coverage    | list  | Áreas com cobertura incompleta           |
| recommendations     | list  | Próximos passos sugeridos                |

## Regras

1. **Não marcar como lacuna o que já tem ferramenta** — se GraphQL foi
   detectado e `graphql_scan` executou, NÃO é lacuna (ver tabela de
   cobertura no skill de triage).
2. **Severidade da lacuna:**
   - **Alta** — superfície de ataque ampla ou CVEs frequentes (WordPress,
     Jenkins, Elasticsearch, Redis exposto)
   - **Média** — testes customizados necessários (REST APIs, WebSocket,
     aplicações web custom)
   - **Baixa** — servidores genéricos sem indicadores de versão vulnerável
3. **Fases com score baixo** — se a avaliação do judge marcou uma fase como
   "partial" ou "empty", documentar o impacto na cobertura.
4. **Se `user_context` fornecido** — reavaliar prioridade das lacunas
   conforme foco do operador.

## Critérios de Qualidade

| Critério                        | Esperado                              |
|---------------------------------|---------------------------------------|
| Cada lacuna com justificativa   | Tecnologia + por que importa          |
| Recommendations actionáveis     | O que testar manualmente              |
| Sem falsos positivos em lacunas | Não marcar nginx/Apache sem razão     |

## Template

```text
Fase de IDENTIFICAÇÃO DE LACUNAS para: ${target}

Tecnologias detectadas: ${tech_count}
Ferramentas executadas: ${tools_count}
Avaliações de fase: ${evaluations}

${user_context ? "Contexto do operador: " + user_context : ""}

Análise:

1. Para cada tecnologia detectada:
   - Existe ferramenta especializada no pipeline?
   - Se existe: foi executada com sucesso?
   - Se não existe: qual é o risco? O que um auditor deveria testar?

2. Para cada fase avaliada:
   - Score < 0.4: impacto crítico na cobertura
   - Score 0.4-0.7: cobertura parcial, documentar gaps

3. Coverage map:
   - Hosts escaneados vs hosts descobertos: ${coverage_pct}%
   - Portas com service version: ${version_pct}%

Formato: lista de unassessed_areas com technology, detected_by,
reason, recommendation e severity.
```
