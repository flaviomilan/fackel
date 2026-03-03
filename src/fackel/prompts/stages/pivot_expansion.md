# Stage — Expansão de Pivôs

## Objetivo

A partir de dados já coletados, identificar e explorar novos vetores
de investigação — IPs históricos, subdomínios relacionados, cloud assets,
registros DNS alterados, domínios irmãos sob o mesmo registrante.

## Inputs

| Campo             | Tipo       | Obrigatório | Descrição                            |
|-------------------|------------|-------------|--------------------------------------|
| current_state     | dict       | sim         | Estado acumulado do scan             |
| historical_dns    | list[dict] | sim         | Registros A/MX/NS históricos         |
| ip_classifications| list[dict] | sim         | Classificação de IPs atuais          |
| tls_certificates  | list[dict] | sim         | SANs de certificados TLS             |
| user_context      | string     | não         | Direcionamento do operador           |

## Outputs

| Campo            | Tipo        | Descrição                                  |
|------------------|-------------|--------------------------------------------|
| new_targets      | list[str]   | IPs/domínios candidatos à investigação     |
| pivot_reasoning  | list[dict]  | Por que cada pivô foi selecionado          |
| discarded_pivots | list[dict]  | Pivôs considerados mas descartados         |

## Regras

1. **Somente pivôs dentro do escopo** — nunca adicionar alvos fora do
   escopo autorizado.  Se um pivô aponta para infraestrutura de terceiros,
   documentar mas NÃO escanear.
2. **Prioridade de pivôs:**
   - IPs históricos que ainda resolvem → alto valor (possível origin bypass)
   - SANs de TLS com subdomínios não descobertos → médio valor
   - Domínios irmãos (mesmo registrante/ASN) → documentar apenas
   - Cloud assets encontrados em JS/source → médio valor
3. **Evidência obrigatória** — cada pivô deve citar a fonte da informação
   (SecurityTrails, TLS SAN, crt.sh, etc.).
4. **Se `user_context` fornecido** — ajustar foco dos pivôs conforme
   direcionamento (ex: "buscar infra legada" → priorizar IPs históricos).

## Critérios de Qualidade

| Critério                          | Mínimo Esperado                    |
|-----------------------------------|------------------------------------|
| IPs históricos verificados        | Todos do SecurityTrails            |
| SANs TLS verificados              | Todos de tlscert_lookup            |
| Cada pivô com justificativa       | Sim                                |
| Pivôs fora do escopo documentados | Sim, sem escaneamento              |

## Template

```text
Fase de EXPANSÃO DE PIVÔS para: ${target}

Dados históricos disponíveis:
- SecurityTrails A records: ${historical_a_count}
- SANs de certificados: ${tls_sans_count}
- Cloud assets: ${cloud_assets_count}

${user_context ? "Contexto do operador: " + user_context : ""}

Análise:
1. Para cada IP histórico que difere dos IPs atuais:
   - Verificar se ainda resolve (dns_resolve)
   - Se sim: candidato a origin IP (bypass CDN/WAF)
2. Para cada SAN em certificados TLS:
   - Se não está na lista de subdomínios: adicionar
3. Para cloud assets (S3, Azure, GCP):
   - Verificar permissões (s3scanner_scan)

Cada pivô selecionado deve ter:
- Fonte (qual ferramenta/registro)
- Justificativa (por que é relevante)
- Risco (o que poderia revelar)

Formato: lista de pivôs priorizados com reasoning.
```
