# Strategy — Ajuste de Profundidade

## Objetivo

Decidir dinamicamente o nível de profundidade de investigação por área,
balanceando thoroughness com eficiência baseado nos achados intermediários.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `findings_by_area`   | `dict`       | Achados agrupados por área              |
| `severity_by_area`   | `dict`       | Severidade máxima por área              |
| `tools_executed`     | `dict`       | Tools já executadas por área            |
| `budget_remaining`   | `dict`       | Budget restante                         |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `depth_settings`     | `dict`       | Nível de profundidade por área (1-5)    |
| `deep_dive_areas`    | `list[str]`  | Áreas marcadas para investigação profunda|
| `shallow_areas`      | `list[str]`  | Áreas marcadas para coverage mínima     |
| `rationale`          | `dict`       | Justificativa por área                  |

## Regras

1. **Níveis de profundidade**:
   - **5 (Exaustivo)**: Todas as tools, todos os params, máxima cobertura.
     Usar quando: vuln critical encontrada, dados sensíveis expostos.
   - **4 (Profundo)**: Tools principais + secundárias, scans detalhados.
     Usar quando: achados high severity, superfície interessante.
   - **3 (Padrão)**: Tools principais, coverage adequada.
     Usar quando: achados moderate, superfície normal.
   - **2 (Superficial)**: Somente tools essenciais, scan rápido.
     Usar quando: poucos achados, baixo risco.
   - **1 (Mínimo)**: Apenas fingerprinting, sem scan ativo.
     Usar quando: área de baixo interesse, budget limitado.
2. **Achados elevam profundidade** — área com vuln critical vai para 5.
3. **Ausência reduz profundidade** — 3+ tools sem achados → reduzir a 2.
4. **Budget limita máximo** — se <20% budget, máximo profundidade 3.
5. **Nunca reduzir** área com vuln critical confirmada.

## Critérios de Qualidade

- Cada área com nível justificado.
- Budget awareness incluída na decisão.
- Áreas de deep dive limitadas a 2-3 simultaneamente.
- Decisões reversíveis se novos dados mudam o quadro.

## Template

```
AJUSTE DE PROFUNDIDADE
=======================

| Área             | Nível Atual | Achados | Sev. Max | Novo Nível | Razão              |
|------------------|-------------|---------|----------|------------|---------------------|
| Web Application  | 3           | 5       | critical | 5          | CVE confirmado      |
| Network          | 3           | 2       | medium   | 3          | Manter padrão       |
| OSINT            | 3           | 0       | —        | 2          | Sem achados         |
| Cloud            | 2           | 1       | high     | 4          | S3 bucket público   |

Deep dive: [Web Application, Cloud]
Budget restante: ${budget}%
```
