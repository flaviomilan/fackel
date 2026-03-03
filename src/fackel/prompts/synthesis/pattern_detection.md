# Synthesis — Detecção de Padrões

## Objetivo

Identificar padrões recorrentes nos achados que indicam problemas
sistêmicos, práticas inseguras ou vulnerabilidades organizacionais.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `all_findings`       | `list[dict]` | Todos achados validados                 |
| `entity_profiles`    | `list[dict]` | Perfis de entidades                     |
| `technology_stack`   | `dict`       | Stack tecnológico do alvo               |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `patterns`           | `list[dict]` | Padrões identificados                   |
| `systemic_issues`    | `list[dict]` | Problemas sistêmicos                    |
| `recommendations`    | `list[dict]` | Recomendações baseadas em padrões       |

## Regras

1. **Tipos de padrão**:
   - **Version lag**: múltiplos serviços desatualizados → patch management falho.
   - **Config repeat**: mesma misconfiguration em múltiplos hosts → template
     de deploy inseguro.
   - **Missing controls**: ausência consistente de security headers →
     processo de hardening ausente.
   - **Exposure pattern**: dev/staging em produção → CI/CD leaking.
   - **Credential hygiene**: múltiplos breaches → política de senhas fraca.
2. **Padrão requer 3+ instâncias** — 2 é coincidência, 3 é padrão.
3. **Padrões sistêmicos > achados individuais** para recomendações.
4. **Priorizar por impacto** — padrão que afeta 10 hosts > padrão em 3 hosts.
5. **Não inferir padrões de dados insuficientes**.

## Critérios de Qualidade

- Cada padrão com 3+ evidências concretas.
- Distinção entre padrão confirmado e tendência observada.
- Recomendações endereçam a causa raiz, não sintomas.
- Padrões priorizados por impacto e remediabilidade.

## Template

```
DETECÇÃO DE PADRÕES
====================

Padrão: [nome descritivo]
Tipo: [version_lag | config_repeat | missing_controls | exposure | credential]
Instâncias: [N]
Evidências:
  - [host1]: [achado específico]
  - [host2]: [achado específico]
  - [host3]: [achado específico]
Impacto: [descrição do risco sistêmico]
Causa raiz provável: [hipótese]
Recomendação: [ação corretiva que endereça a causa raiz]
Prioridade: [alta | média | baixa]
```
