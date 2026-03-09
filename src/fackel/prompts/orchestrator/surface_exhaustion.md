# Orchestrator — Exaustão de Superfície

## Objetivo

Avaliar se a superfície de ataque do alvo foi suficientemente explorada,
identificando áreas com cobertura inadequada que requerem investigação
adicional.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `scope`              | `dict`       | Escopo total (hosts, domínios, IPs)     |
| `tools_executed`     | `dict`       | Tools executadas por alvo               |
| `findings_coverage`  | `dict`       | Cobertura de achados por categoria      |
| `expected_coverage`  | `dict`       | Cobertura mínima esperada               |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `exhaustion_score`   | `float`      | Score de exaustão (0-100%)              |
| `uncovered_areas`    | `list[dict]` | Áreas com cobertura insuficiente        |
| `recommended_tools`  | `list[dict]` | Tools recomendadas para cobrir lacunas  |
| `sufficient`         | `bool`       | Se cobertura é suficiente para report   |

## Regras

1. **Categorias de cobertura**:
   - Subdomínios: coberto quando 3+ fontes consultadas
   - Portas: coberto quando naabu + nmap executados
   - Vulns: coberto quando nuclei + tech-specific scanner executados
   - OSINT: coberto quando APIs + breach + WHOIS executados
   - Web: coberto quando crawling + fingerprinting + XSS executados
2. **Score mínimo para report: 70%** — abaixo disso, continuar
   investigação.
3. **Categorias críticas** (subdomínios, portas, vulns) precisam de
   cobertura >= 80%.
4. **Categorias informacionais** (OSINT, breach) aceitam cobertura 50%.
5. **Não marcar como coberto** se todas as tools da categoria falharam.

## Critérios de Qualidade

- Score reflete cobertura real, não quantidade de tools executadas.
- Áreas não cobertas com recomendação específica.
- Distinção entre "não coberto" e "coberto sem achados" (resultado válido).

## Template

```
EXAUSTÃO DE SUPERFÍCIE
=======================

Cobertura por categoria:
| Categoria     | Score | Status    | Lacuna                |
|---------------|-------|-----------|----------------------|
| Subdomínios   | 90%   | OK        | —                    |
| Portas        | 85%   | OK        | —                    |
| Vulns         | 60%   | LACUNA    | Falta testssl        |
| OSINT         | 70%   | OK        | —                    |
| Web           | 45%   | LACUNA    | Falta XSS scan       |

Score geral: [média ponderada]%
Suficiente para report: [sim/não]

Ações recomendadas para lacunas:
1. [categoria] → executar [tool] (estimativa: +[x]% cobertura)
```
