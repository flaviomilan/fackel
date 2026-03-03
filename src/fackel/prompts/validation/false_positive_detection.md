# Validation — Detecção de Falsos Positivos

## Objetivo

Identificar e filtrar achados que são provavelmente falsos positivos,
reduzindo ruído no relatório final e mantendo alta precisão.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `findings`           | `list[dict]` | Todos os achados brutos                 |
| `source_ratings`     | `dict`       | Rating de confiabilidade das fontes     |
| `context`            | `dict`       | Contexto do alvo (tecnologias, WAF)     |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `confirmed`          | `list[dict]` | Achados confirmados como verdadeiros    |
| `likely_fp`          | `list[dict]` | Prováveis falsos positivos              |
| `uncertain`          | `list[dict]` | Achados que requerem verificação manual |
| `fp_rate`            | `float`      | Taxa estimada de falsos positivos       |

## Regras

1. **Indicadores de falso positivo**:
   - Nuclei finding sem evidência no response body.
   - Vuln para tecnologia não detectada no alvo.
   - XSS "encontrado" mas WAF bloqueia payload.
   - Porta "aberta" que não responde a connections.
   - CVE para versão que não match a detectada.
2. **Não descartar automaticamente** — marcar como likely_fp, não deletar.
3. **Correlação reduz FP** — achado confirmado por 2+ tools com evidência
   independente não é FP.
4. **Context matters** — vuln de Apache em servidor nginx é FP.
5. **Na dúvida, manter** — uncertain é melhor que FP descartado real.
6. **Documentar razão** — cada FP com justificativa explícita.

## Critérios de Qualidade

- Todo achado classificado (confirmed, likely_fp, uncertain).
- Nenhum achado descartado silenciosamente.
- FP rate documentado como métrica de qualidade.
- Razão específica por FP (não "parece falso positivo").

## Template

```
DETECÇÃO DE FALSOS POSITIVOS
==============================

Para cada achado:
1. Verificar evidência: existe prova concreta no response?
2. Verificar contexto: tecnologia match? Versão match?
3. Verificar confirmação: outra tool confirma?
4. Verificar WAF: payload foi bloqueado?

Classificar:
- CONFIRMED: evidência + contexto + confirmação
- LIKELY_FP: sem evidência OU contexto errado OU WAF bloqueou
- UNCERTAIN: evidência parcial, sem confirmação cruzada

| Achado              | Tool    | Evidência | Contexto | Confirm. | Class.      |
|---------------------|---------|-----------|----------|----------|-------------|
| CVE-2024-1234       | nuclei  | ✅        | ✅       | ✅       | CONFIRMED   |
| XSS em /search      | dalfox  | ❌        | ✅       | ❌       | LIKELY_FP   |
| SSH vuln            | shodan  | ❌        | ❌       | ❌       | LIKELY_FP   |

FP rate: [likely_fp / total]%
```
