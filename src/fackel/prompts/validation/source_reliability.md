# Validation — Confiabilidade de Fonte

## Objetivo

Avaliar a confiabilidade de cada fonte de dados (ferramenta/API) no
contexto específico do assessment, considerando precisão histórica,
recência e tipo de dado.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `sources`            | `list[dict]` | Fontes utilizadas com metadados         |
| `findings_by_source` | `dict`       | Achados por fonte                       |
| `confirmation_rates` | `dict`       | Taxa de confirmação cruzada por fonte   |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `source_ratings`     | `dict`       | Rating de confiabilidade por fonte (A-E)|
| `weight_matrix`      | `dict`       | Peso numérico por fonte (0.0-1.0)      |
| `unreliable_sources` | `list[str]`  | Fontes marcadas como não confiáveis     |

## Regras

1. **Classificação de confiabilidade**:
   - **A (1.0)**: Scan direto, confirmado (nmap, nuclei com evidência)
   - **B (0.8)**: Scan direto, sem confirmação cruzada
   - **C (0.6)**: API passiva com dados recentes (<30 dias)
   - **D (0.4)**: API passiva com dados antigos (>30 dias)
   - **E (0.2)**: Fonte única sem confirmação, dados antigos
2. **Recência degrada confiança** — dados de >6 meses perdem 50% do peso.
3. **Confirmação cruzada aumenta confiança** — se 2+ fontes concordam,
   ambas sobem 1 nível.
4. **Falhas consecutivas rebaixam** — fonte que falhou 3+ vezes no
   assessment recebe peso 0.1.
5. **Contexto importa** — Shodan é confiável para portas, não para
   vulnerabilidades. Avaliar por tipo de dado.

## Critérios de Qualidade

- Toda fonte com rating explícito.
- Rating justificado com métricas do assessment atual.
- Fontes não confiáveis identificadas para excluir de decisões.

## Template

```
CONFIABILIDADE DE FONTE
========================

| Fonte          | Tipo        | Achados | Confirmados | Recência  | Rating |
|----------------|-------------|---------|-------------|-----------|--------|
| nmap_port_scan | scan direto | 15      | 14/15       | agora     | A      |
| shodan_lookup  | API passiva | 8       | 5/8         | 45 dias   | D      |
| subfinder      | scan direto | 42      | 38/42       | agora     | A      |

Fontes não confiáveis: [lista com razão]
Peso matrix: {fonte: peso}
```
