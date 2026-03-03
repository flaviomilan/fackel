# Stage — Refinamento de Escopo

## Objetivo

Reavaliar e ajustar o escopo da investigação com base nos achados
intermediários, priorizando áreas de alto risco e removendo linhas
de investigação improdutivas.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `current_scope`      | `dict`       | Escopo atual (hosts, domínios, IPs)     |
| `findings_summary`   | `dict`       | Resumo de achados por categoria         |
| `hypotheses`         | `list[dict]` | Hipóteses pendentes                     |
| `resource_budget`    | `dict`       | Orçamento restante (tools, tempo)       |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `refined_scope`      | `dict`       | Escopo atualizado                       |
| `added_targets`      | `list[str]`  | Novos alvos adicionados                 |
| `removed_targets`    | `list[str]`  | Alvos removidos com justificativa       |
| `priority_shifts`    | `list[dict]` | Mudanças de prioridade com razão        |
| `rationale`          | `string`     | Justificativa geral do refinamento      |

## Regras

1. **Nunca expandir sem evidência** — novos alvos somente se descobertos
   durante reconhecimento autorizado.
2. **Remover dead-ends** — hosts unreachable, domínios parking, IPs sem
   serviços → remover do escopo ativo.
3. **Priorizar superfície rica** — hosts com múltiplas portas, CMS
   desatualizados, vulns confirmadas recebem mais foco.
4. **Respeitar orçamento** — se recursos limitados, focar nos top-3
   alvos de maior risco.
5. **Documentar mudanças** — toda alteração de escopo com justificativa
   clara baseada em evidência.
6. **Não remover alvos com vulns confirmadas** — mesmo que pareçam
   menos interessantes.

## Critérios de Qualidade

- Escopo final menor ou igual ao inicial (não expandir sem justificativa).
- Cada remoção justificada com evidência.
- Cada adição rastreável a um achado específico.
- Prioridades refletem risco real, não complexidade.

## Template

```
REFINAMENTO DE ESCOPO
=====================

1. Revisar escopo atual vs achados:
   - Quais alvos tiveram resultados significativos?
   - Quais alvos são dead-ends?

2. Avaliar descobertas que expandem escopo:
   - Novos subdomínios com serviços ativos?
   - IPs relacionados com superfície interessante?

3. Aplicar filtros:
   - Remover: unreachable, parking, out-of-scope
   - Manter: vulns confirmadas, superfície rica
   - Adicionar: somente se autorizado e evidenciado

4. Re-priorizar:
   - Tier 1: vulns confirmadas, serviços críticos
   - Tier 2: superfície ampla, tecnologia desatualizada
   - Tier 3: informacional, baixo risco

Output: escopo refinado com changelog e justificativas.
```
