# Tool — Cloud Enumeration

## Objetivo

Descobrir recursos cloud expostos (buckets S3, Azure blobs, GCP storage)
e infraestrutura cloud associada ao alvo.

## Ferramentas

| Ferramenta          | Propósito                                        |
|---------------------|--------------------------------------------------|
| `cloudbrute_enum`   | Brute-force de buckets/containers em múltiplos providers |
| `s3scanner_scan`    | Verificação de permissões de buckets S3          |

## Regras de Uso

1. **cloudbrute primeiro** — descobrir nomes de buckets usando wordlist
   baseada no nome da organização, domínio e padrões comuns.
2. **s3scanner nos buckets encontrados** — verificar permissões
   (list, read, write).
3. **Verificar objetos públicos** — buckets com listagem habilitada são
   risco alto.
4. **Não baixar conteúdo** — apenas listar, documentar presença.

## Limites de Escopo

- Somente nomes derivados da organização alvo.
- Não tentar escrita em buckets (somente leitura passiva).
- Não acessar conteúdo sensível encontrado.
- Documentar permissões misconfigured sem exploração.

## Estratégia de Fallback

| Cenário                    | Ação                                       |
|----------------------------|--------------------------------------------|
| cloudbrute muito lento     | Reduzir wordlist a top-100 patterns        |
| s3scanner sem resultados   | Tentar variações do nome (org-backup, org-dev) |
| Rate limit AWS             | Throttle requests, documentar              |
| Nenhum bucket encontrado   | Documentar ausência — resultado válido     |

## Estrutura de Output

```json
{
  "tool": "s3scanner_scan",
  "target": "example-corp",
  "data": {
    "buckets": [
      {
        "name": "example-corp-backup",
        "provider": "aws",
        "region": "us-east-1",
        "permissions": {
          "list": true,
          "read": true,
          "write": false
        },
        "public": true,
        "object_count": 1523
      }
    ],
    "total_found": 3,
    "public_count": 1
  }
}
```

## Normalização

- Provider padronizado: aws, azure, gcp.
- Region em formato oficial do provider.
- Permissões como booleanos explícitos.

## Anomalias

- **Bucket público com read** → exposição de dados, risco alto.
- **Bucket com write** → potencial para upload malicioso, risco crítico.
- **Nomes com "backup", "dump", "db"** → possível dados sensíveis.
- **Bucket em região inesperada** → possível shadow IT ou compliance issue.
- **Bucket com muitos objetos** → potencial para data leak massivo.
