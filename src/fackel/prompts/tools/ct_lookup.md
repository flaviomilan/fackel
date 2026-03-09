# Tool — Certificate Transparency Lookup

## Objetivo

Descobrir certificados emitidos para domínios do alvo via Certificate
Transparency logs, identificando subdomínios, wildcard certs e emissores.

## Ferramentas

| Ferramenta        | Propósito                                      |
|-------------------|-------------------------------------------------|
| `crtsh_subdomain_enum` | Consulta crt.sh (CT logs públicos)        |
| `tlscert_lookup`       | Captura certificado TLS direto do host    |

## Regras de Uso

1. **crt.sh é a fonte primária** — consultar para o domínio-raiz.
2. **tlscert_grab complementa** — capturar cert direto para validar SAN,
   emissor, datas de validade.
3. **Extrair domínios do SAN** — Subject Alternative Names frequentemente
   revelam subdomínios não listados em DNS público.
4. **Cruzar com subdomain_enum** — CT logs revelam domínios que outras
   fontes não encontram.

## Limites de Escopo

- Somente certificados do domínio autorizado.
- Não seguir domínios de terceiros encontrados no SAN.
- Certificados expirados são informativos (documentar, não descartar).

## Estratégia de Fallback

| Cenário             | Ação                                       |
|---------------------|--------------------------------------------|
| crt.sh timeout      | Retry 1x, usar cache se disponível         |
| crt.sh rate limit   | Esperar 30s, retry                         |
| Host não serve TLS  | Documentar — possível serviço HTTP-only    |
| Cert self-signed    | Documentar — indicador de ambiente de dev  |

## Estrutura de Output

```json
{
  "tool": "crtsh_subdomain_enum",
  "target": "example.com",
  "data": {
    "certificates": [
      {
        "id": 12345678,
        "common_name": "*.example.com",
        "san": ["example.com", "www.example.com", "api.example.com"],
        "issuer": "Let's Encrypt Authority X3",
        "not_before": "2025-01-01",
        "not_after": "2025-04-01"
      }
    ],
    "unique_domains": ["example.com", "www.example.com", "api.example.com"],
    "total_certs": 15
  }
}
```

## Normalização

- Domínios lowercase.
- Remover wildcard prefix (*.domain.com → domain.com) na lista de subdomínios.
- Datas em ISO 8601.
- Deduplicar domínios do SAN.

## Anomalias

- **Certificado expirado em produção** → vulnerabilidade de configuração.
- **Emissores múltiplos** → possível migração de infra ou shadow IT.
- **SAN com domínios internos** (ex: *.corp.example.com) → exposição de
  infraestrutura interna.
- **Certificados recentes para subdomínios desconhecidos** → expansão de
  superfície de ataque.
