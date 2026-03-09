# Synthesis — Correlação de Evidências

## Objetivo

Correlacionar achados de múltiplas ferramentas e fases para construir
uma visão unificada da superfície de ataque, conectando dados isolados
em narrativas de risco coerentes.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `all_findings`       | `list[dict]` | Todos achados validados                 |
| `source_ratings`     | `dict`       | Confiabilidade das fontes               |
| `target_topology`    | `dict`       | Mapa de infraestrutura do alvo          |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `correlations`       | `list[dict]` | Correlações identificadas               |
| `attack_chains`      | `list[dict]` | Cadeias de ataque potenciais            |
| `enriched_findings`  | `list[dict]` | Achados enriquecidos com contexto       |
| `correlation_graph`  | `dict`       | Grafo de relações entre achados         |

## Regras

1. **Tipos de correlação**:
   - **Host correlation**: mesmo IP, diferentes achados → visão completa do host.
   - **Service chain**: serviço desatualizado + CVE conhecida + porta exposta
     → cadeia de ataque.
   - **Credential chain**: email breached + admin panel exposto → credential
     stuffing path.
   - **Infrastructure**: shared hosting + outro tenant vulnerável → lateral
     movement risk.
2. **Correlação requer evidência** — não conectar achados sem base factual.
3. **Attack chains são hipotéticas** — marcar como "potencial", não "confirmado",
   a menos que cada elo seja verificado.
4. **Peso das correlações** — correlações com 3+ evidências têm peso alto.
5. **Não fabricar correlações** — ausência de correlação é resultado válido.

## Critérios de Qualidade

- Cada correlação com lista de evidências que a suportam.
- Attack chains com cada elo atribuído a um achado específico.
- Grafo de correlações sem nós órfãos (achados isolados documentados como tal).
- Distinção clara entre correlação confirmada e hipotética.

## Template

```
CORRELAÇÃO DE EVIDÊNCIAS
=========================

1. Agrupar achados por: host, serviço, domínio, organização
2. Para cada grupo, identificar conexões:
   - Achado A + Achado B → Correlação C (tipo, confiança)
3. Construir cadeias de ataque:
   - [entry point] → [escalation] → [impact]
   - Cada elo referencia achado específico
4. Enriquecer achados com contexto cruzado

Correlações encontradas:
| ID   | Achados Relacionados | Tipo        | Confiança | Cadeia? |
|------|---------------------|-------------|-----------|---------|
| C-01 | F-03, F-12, F-15    | host_chain  | alta      | sim     |
| C-02 | F-07, F-22          | credential  | média     | sim     |

Attack chains:
- Chain 1: [XSS em /login] → [session hijack] → [admin access]
  Evidência: F-03 (XSS), F-15 (admin panel), F-12 (no CSRF token)
```
