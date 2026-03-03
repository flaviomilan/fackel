# Stage — Geração de Hipóteses

## Objetivo

Gerar hipóteses investigativas baseadas nos achados coletados,
identificando padrões, correlações e vetores de ataque potenciais
que requerem investigação adicional.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `classified_findings`| `list[dict]` | Achados com confidence score            |
| `correlations`       | `list[dict]` | Correlações identificadas               |
| `gaps`               | `list[dict]` | Lacunas identificadas                   |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `hypotheses`         | `list[dict]` | Hipóteses com prioridade e plano de teste|
| `test_plans`         | `list[dict]` | Plano de verificação por hipótese       |
| `priority_order`     | `list[str]`  | IDs das hipóteses ordenadas por impacto |

## Regras

1. **Hipótese deve ser testável** — cada hipótese deve ter um plano
   concreto de verificação usando ferramentas disponíveis.
2. **Baseada em evidência** — hipóteses devem derivar de achados reais,
   não suposições genéricas.
3. **Priorizar por impacto** — hipóteses de vulnerabilidade crítica
   antes de information disclosure.
4. **Categorias de hipótese**:
   - Vulnerabilidade exploitable (ex: "RCE via plugin X desatualizado")
   - Misconfiguration (ex: "S3 bucket permite write")
   - Exposição de dados (ex: "Backup files acessíveis publicamente")
   - Infraestrutura compartilhada (ex: "Mesmo IP hospeda outros serviços")
5. **Máximo 10 hipóteses** — focar nas mais impactantes e testáveis.
6. **Cada hipótese com**: descrição, evidência base, ferramentas para
   verificação, risco estimado, esforço de teste.

## Critérios de Qualidade

- Hipóteses específicas e acionáveis (não genéricas).
- Cada hipótese referencia evidência concreta.
- Plano de teste usa ferramentas disponíveis no pipeline.
- Priorização justificada por risco × probabilidade.
- Nenhuma hipótese redundante.

## Template

```
GERAÇÃO DE HIPÓTESES
====================

Analisar corpus de achados e correlações para gerar hipóteses:

1. Identificar padrões nos achados (versões desatualizadas, misconfigs)
2. Para cada padrão, formular hipótese específica:
   - "Se [condição observada], então [consequência potencial]"
3. Definir plano de teste (quais ferramentas, quais inputs)
4. Estimar risco: impacto (1-5) × probabilidade (1-5)
5. Ordenar por score de risco decrescente

Formato por hipótese:
- ID: H-001
- Descrição: [hipótese clara e testável]
- Evidência: [achados que suportam]
- Ferramentas: [tools para verificar]
- Risco estimado: [impacto × probabilidade]
- Status: pending | confirmed | rejected
```
