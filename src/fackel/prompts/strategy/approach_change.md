# Strategy — Mudança de Abordagem

## Objetivo

Adaptar a abordagem técnica quando a estratégia atual não está produzindo
resultados, incluindo mudança de ferramentas, técnicas ou ângulo de ataque.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `current_approach`   | `dict`       | Abordagem atual (tools, técnicas)       |
| `success_rate`       | `float`      | Taxa de sucesso da abordagem atual      |
| `blocking_factors`   | `list[dict]` | Fatores bloqueando progresso            |
| `available_alternatives`| `list[dict]`| Ferramentas/técnicas alternativas     |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `new_approach`       | `dict`       | Nova abordagem                          |
| `changes`            | `list[dict]` | Mudanças aplicadas                      |
| `expected_improvement`| `string`    | Melhoria esperada                       |
| `rollback_plan`      | `string`     | Plano se nova abordagem também falhar   |

## Regras

1. **Triggers para mudança de abordagem**:
   - WAF bloqueando todas as tools ativas → mudar para técnicas passivas.
   - Timeout sistemático → mudar para tools mais leves/rápidas.
   - Falso positivo rate > 50% → mudar para tools mais precisas.
   - Alvo não responde a scanning → pivotar para OSINT/API.
2. **Mudanças possíveis**:
   - Tool substitution (nuclei → nikto, feroxbuster → dirsearch).
   - Technique change (brute-force → crawling, active → passive).
   - Angle change (web → network, external → OSINT-only).
   - Parameter tuning (rate, timeout, wordlist).
3. **Tentar mudança menor primeiro** — params antes de tool, tool antes
   de técnica.
4. **Rollback plan obrigatório** — se nova abordagem falha, o que fazer?
5. **Máximo 2 mudanças de abordagem** por assessment — instabilidade
   reduz qualidade.

## Critérios de Qualidade

- Mudança motivada por dados, não frustração.
- Mudança menor tentada antes de mudança maior.
- Rollback plan documentado.
- Expectativa de melhoria fundamentada.

## Template

```
MUDANÇA DE ABORDAGEM
=====================

Abordagem atual: ${current_approach}
Taxa de sucesso: ${success_rate}%
Fator bloqueante: ${blocking_factor}

Mudança proposta:
| Aspecto      | Antes           | Depois            | Razão          |
|--------------|-----------------|-------------------|----------------|
| Ferramenta   | nuclei          | nikto             | WAF blocking   |
| Rate         | 10/s            | 2/s               | Rate limit     |
| Técnica      | brute-force     | crawling          | 403 em tudo    |

Melhoria esperada: [descrição com base]
Rollback: se falhar, [plano alternativo]
```
