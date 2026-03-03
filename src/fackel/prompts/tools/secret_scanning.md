# Tool — Secret Scanning

## Objetivo

Detectar segredos expostos (API keys, tokens, senhas, chaves privadas)
em repositórios de código, endpoints e conteúdo web do alvo.

## Ferramentas

| Ferramenta          | Propósito                                       |
|---------------------|-------------------------------------------------|
| `trufflehog_scan`   | Scanning de segredos em repos git e URLs        |

## Regras de Uso

1. **Executar em todo repositório público** do alvo encontrado.
2. **Scan completo do histórico git** — segredos removidos em commits
   posteriores ainda podem ser válidos.
3. **Classificar por tipo** — AWS keys, GitHub tokens, database URLs,
   cada tipo tem impacto diferente.
4. **Validar quando possível** — truffle hog verifica se keys ainda
   são ativas (quando safe verification disponível).
5. **Prioridade máxima** — segredos válidos são risco imediato.

## Limites de Escopo

- Somente repositórios públicos do alvo.
- Não acessar repositórios privados.
- Não testar credenciais encontradas em sistemas de produção.
- Regex patterns genéricos geram falsos positivos — classificar
  com confidence score.

## Estratégia de Fallback

| Cenário                   | Ação                                      |
|---------------------------|-------------------------------------------|
| Repositório muito grande  | Limitar a branches main/master + tags     |
| Sem repos públicos        | Scan de JS em endpoints web               |
| Rate limit GitHub         | Usar API token se disponível              |
| Muitos false positives    | Filtrar por entropia e pattern matching   |

## Estrutura de Output

```json
{
  "tool": "trufflehog_scan",
  "target": "https://github.com/org/repo",
  "data": {
    "secrets": [
      {
        "type": "AWS Access Key",
        "file": "config/settings.py",
        "commit": "abc123",
        "line": 42,
        "verified": true,
        "severity": "critical"
      }
    ],
    "total_secrets": 3,
    "verified_count": 1,
    "types_found": ["AWS Access Key", "GitHub Token", "Generic Password"]
  }
}
```

## Normalização

- Tipo de secret padronizado (AWS Access Key, GitHub Token, etc.).
- Commit hash completo (40 chars).
- Severity: critical (verified active), high (plausible), medium (pattern match).

## Anomalias

- **Secret verificado como ativo** → report imediato, risco máximo.
- **Múltiplos tipos de secret no mesmo repo** → práticas de segurança
  deficientes.
- **Secret em commit recente** → possivelmente ainda em uso.
- **AWS/GCP keys** → potencial comprometimento de cloud completo.
- **Database URLs com credenciais** → acesso direto a dados.
