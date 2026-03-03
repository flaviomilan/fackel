# Validation — Detecção de Inconsistências

## Objetivo

Identificar contradições e inconsistências entre dados coletados por
diferentes ferramentas, sinalizando achados que requerem reconciliação.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `findings_by_tool`   | `dict`       | Achados agrupados por ferramenta        |
| `cross_references`   | `dict`       | Referências cruzadas entre achados      |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                  | Tipo         | Descrição                             |
|------------------------|--------------|---------------------------------------|
| `inconsistencies`      | `list[dict]` | Lista de inconsistências detectadas   |
| `reconciled`           | `list[dict]` | Inconsistências resolvidas            |
| `unresolved`           | `list[dict]` | Inconsistências que requerem decisão  |
| `data_quality_score`   | `float`      | Score de qualidade dos dados (0-100)  |

## Regras

1. **Tipos de inconsistência**:
   - **Contradição direta**: Tool A diz porta 80 aberta, Tool B diz fechada.
   - **Versão divergente**: httpx diz nginx/1.24, nmap diz nginx/1.22.
   - **Status divergente**: Shodan diz vuln exists, nuclei não confirma.
   - **Temporal**: dados de APIs desatualizados vs scan direto recente.
2. **Scan direto tem precedência** sobre API passiva em caso de conflito.
3. **Dado mais recente tem precedência** (com exceções para flapping).
4. **Não descartar nenhum lado** — documentar ambos com atribuição.
5. **Score de qualidade reduz** com cada inconsistência não resolvida.

## Critérios de Qualidade

- Toda inconsistência categorizada por tipo.
- Resolução justificada (qual fonte é mais confiável e por quê).
- Inconsistências não resolvidas explicitamente marcadas.
- Não mascarar problemas de qualidade.

## Template

```
DETECÇÃO DE INCONSISTÊNCIAS
============================

Para cada par de achados sobre o mesmo alvo/fato:
1. Comparar valores (porta, versão, status, tecnologia)
2. Se divergência encontrada:
   - Tipo: [contradição | versão | status | temporal]
   - Fonte A: [tool] → [valor] (timestamp)
   - Fonte B: [tool] → [valor] (timestamp)
   - Resolução: [A prevalece | B prevalece | ambos documentados]
   - Razão: [scan direto > API | mais recente | mais específico]

Score de qualidade = 100 - (inconsistências_não_resolvidas × 5)
```
