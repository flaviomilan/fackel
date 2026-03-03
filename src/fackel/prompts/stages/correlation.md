# Stage — Correlação

## Objetivo

Cruzar dados de múltiplas fontes para identificar relações entre entidades
descobertas — quais IPs hospedam quais domínios, quais serviços compartilham
certificados, quais tecnologias aparecem em múltiplos hosts.

## Inputs

| Campo       | Tipo  | Obrigatório | Descrição                                  |
|-------------|-------|-------------|--------------------------------------------|
| findings    | list  | sim         | Achados de todas as fases anteriores        |
| ips         | list  | sim         | IPs com classificação e metadados          |
| subdomains  | list  | sim         | Subdomínios com resolução DNS              |
| services    | list  | sim         | Serviços e versões por IP:porta            |
| tech_stack  | list  | sim         | Tecnologias detectadas por host            |

## Outputs

| Campo              | Tipo  | Descrição                                    |
|--------------------|-------|----------------------------------------------|
| entity_groups      | list  | Clusters de entidades relacionadas            |
| shared_infra       | list  | Infraestrutura compartilhada detectada        |
| cross_references   | list  | Referências cruzadas entre achados            |
| inconsistencies    | list  | Contradições entre fontes distintas           |

## Regras

1. **Somente dados factuais** — correlações devem ser baseadas em evidência
   direta, não em suposição.
2. **Fontes múltiplas** — uma correlação forte requer confirmação de ≥ 2
   fontes independentes.
3. **Contradições são valiosas** — se fonte A diz X e fonte B diz Y,
   documentar a inconsistência.
4. **Tipos de correlação:**
   - IP→domínio (reverse DNS, shared hosting)
   - Certificado→domínio (SANs compartilhados)
   - ASN→organização (proprietário comum)
   - Tecnologia→versão (mesma stack em múltiplos hosts)
   - Temporal (dados históricos vs atuais)

## Critérios de Qualidade

| Critério                     | Esperado                                  |
|------------------------------|-------------------------------------------|
| Cada correlação com fontes   | ≥ 2 fontes citadas                        |
| Inconsistências documentadas | Todas com ambas as fontes citadas         |
| Clusters coerentes           | Sem entidades duplicadas entre clusters   |

## Template

```text
Fase de CORRELAÇÃO para: ${target}

Dados disponíveis:
- ${ips_count} IPs, ${subdomains_count} subdomínios
- ${services_count} serviços, ${findings_count} achados

Execute as seguintes correlações:

1. Mapeamento IP→domínio: quais domínios resolvem para cada IP?
2. Hosting compartilhado: IPs com shared_domains > 5?
3. Certificados compartilhados: hosts usando o mesmo fingerprint TLS?
4. ASN clustering: hosts sob o mesmo ASN/organização?
5. Stack tecnológico: mesma tecnologia e versão em hosts distintos?
6. Inconsistências: dados conflitantes entre fontes?

Para cada correlação:
- Citar as fontes (ferramenta + dados específicos)
- Classificar confiança: alta (≥3 fontes), média (2 fontes), baixa (1 fonte)
- Se inconsistência: documentar ambos os lados

Formato: agrupamentos de entidades com referências cruzadas.
```
