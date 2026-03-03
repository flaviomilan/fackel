# Stage — Classificação de Confiabilidade

## Objetivo

Avaliar a confiabilidade de cada informação coletada, atribuindo score
de confiança baseado na quantidade de fontes, consistência e recência.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `findings`           | `list[dict]` | Lista de achados com fonte e timestamp  |
| `source_count`       | `dict`       | Contagem de fontes por achado           |
| `cross_validation`   | `dict`       | Resultados de validação cruzada         |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `classified_findings`    | `list[dict]` | Achados com confidence_score (0-100) |
| `high_confidence`        | `list[dict]` | Achados com score >= 80              |
| `low_confidence`         | `list[dict]` | Achados com score < 50               |
| `confidence_distribution`| `dict`       | Distribuição de scores               |

## Regras

1. **Multi-source = alta confiança** — achado confirmado por 3+ fontes
   independentes recebe score >= 80.
2. **Fonte única = baixa confiança** — score máximo 50 para finding de
   fonte única não validada.
3. **Recência importa** — dados de <30 dias têm peso maior que dados de
   >6 meses.
4. **Tipo de fonte afeta peso**:
   - Scan direto (nmap, nuclei) → peso 1.0
   - API passiva (Shodan, Censys) → peso 0.8
   - Histórico (Wayback, CT logs) → peso 0.5
5. **Conflito reduz confiança** — dados conflitantes entre fontes reduzem
   score de ambos em 20%.
6. **Achado sem data** → score máximo 40 (temporalidade desconhecida).

## Critérios de Qualidade

- Todo achado classificado, nenhum sem score.
- Distribuição de confidence documentada.
- Justificativa para scores extremos (>90 ou <20).
- Achados de baixa confiança não descartados, apenas classificados.

## Template

```
CLASSIFICAÇÃO DE CONFIABILIDADE
===============================

Para cada achado:
1. Contar fontes independentes que confirmam
2. Avaliar recência dos dados
3. Verificar consistência entre fontes
4. Calcular score: base(fontes) * peso(tipo) * recência * consistência
5. Classificar: alta (>=80), média (50-79), baixa (<50)

Regras de score:
- 3+ fontes concordantes, dados recentes → 80-100
- 2 fontes concordantes → 60-79
- 1 fonte confiável (scan direto) → 40-59
- 1 fonte passiva → 20-39
- Dados conflitantes → reduzir 20% do score base

Output: lista classificada com score e justificativa por achado.
```
