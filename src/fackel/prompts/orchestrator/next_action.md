# Orchestrator — Próxima Ação

## Objetivo

Decidir qual ferramenta ou conjunto de ferramentas executar a seguir,
baseado no estado atual do pipeline, achados coletados e lacunas
identificadas.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `pipeline_state`     | `dict`       | Estado atual (fase, ferramentas já executadas) |
| `findings_so_far`    | `list[dict]` | Achados coletados até agora             |
| `gaps`               | `list[dict]` | Lacunas identificadas                   |
| `available_tools`    | `list[str]`  | Ferramentas disponíveis                 |
| `budget_remaining`   | `dict`       | Chamadas/tempo restantes                |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `next_actions`       | `list[dict]` | Ações ordenadas por prioridade          |
| `rationale`          | `string`     | Justificativa para a decisão            |
| `parallel_batch`     | `list[str]`  | Tools que podem executar em paralelo    |
| `skip_list`          | `list[str]`  | Tools que não precisam executar + razão |

## Regras

1. **Dados antes de scan** — priorizar reconhecimento passivo antes de
   scanning ativo.
2. **Dependências respeitadas**:
   - Subdomain enum → DNS resolution → HTTP probing → Vuln scanning
   - Port scan → Service detection → Version-specific vuln scan
3. **Máximo ROI** — escolher tools que preenchem as maiores lacunas
   com menor custo.
4. **Parallelismo quando possível** — tools independentes em batch.
5. **Evitar redundância** — se subfinder e amass já rodaram, não repetir
   a menos que haja razão específica.
6. **Budget awareness** — se budget está acabando, priorizar tools de
   alto impacto.

## Critérios de Qualidade

- Decisão justificada com referência a estado atual.
- Batch de execução paralela identificado.
- Nenhuma tool executada desnecessariamente.
- Dependências respeitadas (não vuln scan sem service detection).

## Template

```
DECISÃO: PRÓXIMA AÇÃO
======================

1. Avaliar estado atual:
   - Fase: [recon | enumeration | scanning | validation]
   - Tools executadas: [lista]
   - Cobertura atual: [%]

2. Identificar lacunas prioritárias:
   - O que falta para completar a fase atual?
   - Quais achados requerem investigação adicional?

3. Selecionar próximas tools:
   - Quais tools preenchem as lacunas identificadas?
   - Quais podem ser parallelizadas?
   - Quais têm dependências não satisfeitas?

4. Output:
   - Batch paralelo: [tool1, tool2, tool3]
   - Sequenciais: [tool4 → tool5]
   - Skip: [tool6 (razão)]
```
