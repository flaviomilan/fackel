# Strategy — Integração de Contexto do Usuário

## Objetivo

Incorporar contexto adicional fornecido pelo usuário na estratégia de
assessment, ajustando prioridades, escopo e foco baseado em informações
que o pipeline não pode descobrir sozinho.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `user_context`       | `string`     | Contexto livre fornecido pelo usuário   |
| `current_strategy`   | `dict`       | Estratégia atual do pipeline            |
| `pipeline_state`     | `dict`       | Estado atual do pipeline                |

## Outputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `strategy_adjustments`   | `list[dict]` | Ajustes na estratégia                |
| `priority_overrides`     | `list[dict]` | Prioridades alteradas pelo contexto  |
| `additional_targets`     | `list[str]`  | Alvos adicionais do contexto         |
| `exclusions`             | `list[str]`  | Alvos/áreas excluídos pelo usuário   |

## Regras

1. **Tipos de contexto do usuário**:
   - **Escopo**: "focar em api.example.com" → priorizar esse target.
   - **Exclusão**: "não testar payments.example.com" → excluir.
   - **Prioridade**: "preocupação com XSS no formulário de login" → elevar
     prioridade de XSS scanning.
   - **Conhecimento prévio**: "backend é Laravel" → ajustar fingerprinting.
   - **Restrição**: "não fazer port scan agressivo" → limitar agressividade.
   - **Indústria**: "e-commerce com dados de cartão" → PCI DSS compliance.
2. **Contexto complementa, não substitui** — pipeline mantém decisões
   técnicas, contexto ajusta prioridades.
3. **Exclusões são absolutas** — se usuário exclui target, não escanear.
4. **Prioridades são fortes** — contexto do usuário pesa mais que
   heurísticas automáticas.
5. **Validar contexto** — contexto contraditório ou impossível deve ser
   sinalizado, não ignorado.

## Critérios de Qualidade

- Todo contexto do usuário processado e refletido na estratégia.
- Exclusões respeitadas sem exceção.
- Prioridades ajustadas de forma documentada.
- Contexto contraditório sinalizado.
- Impacto do contexto rastreável nos resultados.

## Template

```
INTEGRAÇÃO DE CONTEXTO
========================

Contexto recebido: "${user_context}"

Parsing:
| Tipo            | Informação               | Ação                          |
|-----------------|--------------------------|-------------------------------|
| escopo          | focar em api.example.com | Prioridade 1 para esse target |
| exclusão        | não testar payments      | Excluir de todos os scans     |
| conhecimento    | backend Laravel          | Adicionar templates Laravel   |
| restrição       | sem port scan agressivo  | Limitar a naabu top-1000      |

Ajustes na estratégia:
1. [ajuste + razão baseada no contexto]
2. [ajuste + razão baseada no contexto]

Conflitos detectados: [nenhum | lista]
```
