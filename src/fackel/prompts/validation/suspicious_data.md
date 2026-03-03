# Validation — Dados Suspeitos

## Objetivo

Identificar dados que parecem anômalos, manipulados ou inconsistentes
com o perfil esperado do alvo, sinalizando para investigação adicional.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `findings`           | `list[dict]` | Achados coletados                       |
| `target_profile`     | `dict`       | Perfil do alvo (indústria, tamanho, tech stack) |
| `baseline`           | `dict`       | Baseline esperado para o tipo de alvo   |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `suspicious_data`    | `list[dict]` | Dados marcados como suspeitos           |
| `anomaly_type`       | `list[str]`  | Tipo de anomalia por dado               |
| `investigation_needed`| `list[dict]`| Itens que requerem investigação         |

## Regras

1. **Tipos de dados suspeitos**:
   - **Honeypot indicators**: muitas portas abertas com banners genéricos.
   - **Deception**: responses que mudam a cada request (anti-scanning).
   - **Stale data**: API retornando dados de >1 ano sem atualização.
   - **Manipulated**: headers ou banners deliberadamente enganosos.
   - **Inconsistent scale**: empresa pequena com centenas de subdomínios.
2. **Honeypot detection** — se >50 portas abertas em um IP único, alta
   probabilidade de honeypot.
3. **Banner grabbing inconsistente** — nginx retornando banner de Apache
   sugere proxy ou deception.
4. **Dados de API desatualizados** — Shodan/Censys com last_seen >1 ano
   são suspeitos.
5. **Não descartar, sinalizar** — dados suspeitos são investigados, não
   removidos.

## Critérios de Qualidade

- Cada dado suspeito com tipo de anomalia e justificativa.
- Distinção clara entre "incomum" e "provavelmente falso".
- Investigation path sugerido para cada item.
- Não criar paranoia — falsos alarmes custam tempo.

## Template

```
DADOS SUSPEITOS
================

Para cada achado, verificar:
1. Consistência com perfil do alvo
2. Consistência temporal (dados recentes?)
3. Consistência técnica (banners match serviços?)
4. Consistência de escala (quantidade proporcional?)

Anomalias detectadas:
| Dado                | Tipo Anomalia    | Confiança | Ação Recomendada    |
|---------------------|------------------|-----------|---------------------|
| IP com 80 portas    | honeypot         | alta      | Verificar manualmente|
| nginx→apache banner | banner deception | média     | Re-scan com nmap -sV|
| Shodan data 2023    | stale data       | alta      | Ignorar, scan direto|
```
