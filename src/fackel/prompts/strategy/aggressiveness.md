# Strategy — Agressividade

## Objetivo

Calibrar o nível de agressividade das ferramentas de scanning baseado
no contexto do alvo, WAF detectado, rate limiting e tolerância a ruído.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `target_type`        | `string`     | Tipo: production, staging, dev          |
| `waf_detected`       | `dict`       | WAF info (tipo, agressividade)          |
| `rate_limits`        | `dict`       | Rate limits observados                  |
| `failures`           | `list[dict]` | Falhas por agressividade                |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `aggressiveness`     | `string`     | Nível: passive, cautious, moderate, aggressive |
| `tool_params`        | `dict`       | Parâmetros por ferramenta               |
| `rate_config`        | `dict`       | Rate limits por ferramenta              |
| `rationale`          | `string`     | Justificativa do nível                  |

## Regras

1. **Níveis de agressividade**:
   - **Passive**: somente consultas de API, sem requests ao alvo.
     Quando: fase inicial, alvo sensível, sem autorização para scan ativo.
   - **Cautious**: requests limitadas, User-Agent genérico, rate ≤ 2/s.
     Quando: WAF agressivo, produção com SLA exigente.
   - **Moderate**: scanning normal, rate ≤ 10/s, scripts safe only.
     Quando: padrão para a maioria dos alvos.
   - **Aggressive**: scanning completo, rate ≤ 50/s, scripts vuln.
     Quando: autorização explícita, ambiente de teste.
2. **Downgrade automático** quando:
   - WAF bloqueando >50% dos requests → reduzir 1 nível.
   - Rate limiting detectado → ajustar rate para 50% do limite.
   - Falhas consecutivas por timeout → reduzir 1 nível.
3. **Nunca upgrade** sem autorização explícita.
4. **Production = cautious por padrão** a menos que especificado.
5. **Staging/dev = moderate por padrão**.

## Critérios de Qualidade

- Nível justificado com observações concretas.
- Parâmetros específicos por ferramenta (não genéricos).
- Rate limits calculados, não arbitrários.
- Mecanismo de downgrade claro.

## Template

```
CALIBRAÇÃO DE AGRESSIVIDADE
==============================

Contexto:
- Target type: ${target_type}
- WAF: ${waf_info}
- Rate limits observados: ${rate_limits}
- Falhas por agressividade: ${failures}

Decisão: ${LEVEL}
Razão: [justificativa]

Parâmetros por ferramenta:
| Ferramenta   | Rate (req/s) | Timeout (s) | Params Adicionais      |
|--------------|-------------|-------------|------------------------|
| nmap         | —           | 30          | -T3 (normal)           |
| nuclei       | 10          | 15          | -rl 10                 |
| feroxbuster  | 5           | 10          | -t 5                   |
| katana       | 3           | 20          | -d 3                   |

Regra de downgrade: se >50% falhas, reduzir para ${LEVEL-1}.
```
