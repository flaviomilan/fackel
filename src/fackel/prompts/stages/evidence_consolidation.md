# Stage — Consolidação de Evidências

## Objetivo

Agregar todos os achados validados em uma visão unificada e normalizada
do alvo — o inventário final de inteligência que alimenta a produção
do relatório.

## Inputs

| Campo               | Tipo  | Obrigatório | Descrição                          |
|---------------------|-------|-------------|------------------------------------|
| validated_findings  | list  | sim         | Achados confirmados                |
| entity_groups       | list  | sim         | Clusters de entidades              |
| unassessed_areas    | list  | sim         | Lacunas identificadas              |
| risk_score          | dict  | sim         | Score de exposição calculado       |

## Outputs

| Campo               | Tipo    | Descrição                              |
|---------------------|---------|----------------------------------------|
| consolidated_report | dict    | Inventário final normalizado           |
| evidence_chain      | list    | Cadeia de evidência por achado         |
| confidence_matrix   | list    | Nível de confiança por categoria       |

## Regras

1. **Deduplicação** — o mesmo achado reportado por múltiplas fontes
   deve aparecer UMA vez com todas as fontes citadas.
2. **Evidência citada** — cada afirmação no inventário deve ter referência
   à ferramenta e output específico.
3. **Separação fato vs inferência** — fatos são output direto de
   ferramentas; inferências são correlações derivadas (marcar explicitamente).
4. **Confiança atribuída** — cada item do inventário tem confidence
   (high/medium/low) baseado nas regras de validação cruzada.
5. **Order by severity** — organizar por criticidade decrescente.

## Critérios de Qualidade

| Critério                        | Esperado                              |
|---------------------------------|---------------------------------------|
| Cada achado com cadeia de evidência | Ferramenta → output → conclusão   |
| Sem duplicatas                    | Fingerprint-based dedup             |
| Fatos vs inferências separados    | Marcação explícita                  |
| Severity e confidence atribuídos  | Em 100% dos achados                |

## Template

```text
Fase de CONSOLIDAÇÃO DE EVIDÊNCIAS para: ${target}

Achados validados: ${validated_count}
Clusters de entidades: ${clusters_count}
Lacunas identificadas: ${gaps_count}
Risk score: ${risk_score}/10 (${exposure_type})

Procedimento:

1. Deduplicar achados por fingerprint (tipo + valor normalizado)
2. Para cada achado único:
   - Listar todas as fontes que o confirmam
   - Atribuir confidence (high/medium/low)
   - Classificar severity (critical/high/medium/low/info)
   - Separar em fato vs inferência
3. Agrupar por categoria:
   - Infraestrutura (IPs, DNS, hosting)
   - Serviços (portas, versões, banners)
   - Vulnerabilidades (CVEs, misconfigs)
   - Tecnologias (stack detectada)
   - Inteligência (emails, breaches, leaks)
4. Ordenar cada grupo por severity desc, confidence desc

Formato: inventário estruturado pronto para produção de relatório.
```
