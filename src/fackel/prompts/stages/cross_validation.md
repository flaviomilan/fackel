# Stage — Validação Cruzada

## Objetivo

Verificar a consistência e confiabilidade dos dados coletados comparando
achados entre fontes independentes.  Identificar falsos positivos, dados
desatualizados e informações contraditórias.

## Inputs

| Campo           | Tipo  | Obrigatório | Descrição                              |
|-----------------|-------|-------------|----------------------------------------|
| findings        | list  | sim         | Todos os achados acumulados            |
| source_map      | dict  | sim         | Fonte (ferramenta) de cada achado      |
| cross_refs      | list  | sim         | Correlações da fase anterior           |

## Outputs

| Campo               | Tipo  | Descrição                                |
|---------------------|-------|------------------------------------------|
| validated_findings  | list  | Achados confirmados por ≥ 2 fontes       |
| unconfirmed         | list  | Achados de fonte única — confiança baixa |
| false_positives     | list  | Achados contraditos ou inválidos         |
| stale_data          | list  | Dados possivelmente desatualizados       |

## Regras

1. **Confirmar com múltiplas fontes** — um achado confirmado por subfinder
   E crt.sh tem mais peso que um achado apenas de um serviço.
2. **Verificar temporalidade** — dados de Wayback Machine / SecurityTrails
   podem ser antigos.  Marcar como "possivelmente desatualizado" se não
   confirmado por scan ativo recente.
3. **Falsos positivos comuns:**
   - Subdomínios de crt.sh que não resolvem mais
   - Portas reportadas por Shodan que não confirmam no nmap
   - Vulnerabilidades genéricas de nuclei (info-severity mass templates)
4. **Nunca descartar sem evidência** — se não é possível confirmar nem
   negar, manter como "unconfirmed" com nota de confiança.

## Critérios de Qualidade

| Critério                     | Esperado                               |
|------------------------------|----------------------------------------|
| Cada achado com nível de confiança | alto/médio/baixo atribuído       |
| Falsos positivos justificados | Razão do descarte documentada         |
| Dados temporais verificados   | Alertas em dados > 6 meses            |

## Template

```text
Fase de VALIDAÇÃO CRUZADA para: ${target}

Total de achados: ${total_findings}
Fontes distintas: ${unique_sources}

Para cada achado na coleção:

1. Contar quantas fontes independentes o confirmam.
2. Se ≥ 2 fontes: confidence = "high"
3. Se 1 fonte apenas: confidence = "medium" (scan ativo) ou "low" (passivo)
4. Se contradito por outra fonte: candidato a false_positive
5. Se baseado em dados históricos sem confirmação atual: stale_data

Verificações específicas:
- Subdomínios: resolvem DNS? Se não → possível false_positive
- Portas: confirmadas por scan ativo (nmap)? Se só Shodan → medium
- Vulnerabilidades: template nuclei genérico? Se info-only → manter mas rebaixar
- IPs históricos: ainda respondem? Se não → stale_data

Formato: lista classificada por nível de confiança.
```
