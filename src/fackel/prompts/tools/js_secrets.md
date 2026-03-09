# Tool — JavaScript Secret Scanning

## Objetivo

Detectar segredos, chaves de API, tokens e dados sensíveis
expostos em arquivos JavaScript públicos.

## Ferramentas

| Ferramenta         | Propósito                                          |
|--------------------|----------------------------------------------------|
| `js_secret_scan`   | Scanner regex de segredos em JS (passivo)          |
| `trufflehog_scan`  | Detecção de secrets em repos/URLs via TruffleHog   |
| `linkfinder_extract` | Extração de endpoints e paths de JS             |

## Regras de Uso

1. **js_secret_scan em todos os hosts web** — análise passiva que
   faz apenas GET requests para JS files.
2. **Priorizar páginas com muitos scripts** — SPAs e aplicações
   React/Vue/Angular expõem mais código.
3. **Correlacionar com linkfinder** — endpoints descobertos pelo
   linkfinder podem conter secrets adicionais.
4. **Validar findings** — regex pode gerar false positives;
   confirmar que o match é realmente um secret.

## Priorização de Findings

| Finding                    | Severity   |
|----------------------------|------------|
| AWS Access Key             | critical   |
| GitHub Token               | critical   |
| Stripe Secret Key          | critical   |
| Private Key                | critical   |
| Slack Token/Webhook        | high       |
| JWT Token                  | high       |
| Hardcoded Password         | high       |
| Generic API Key            | medium     |
| Internal IP Address        | medium     |
| Firebase URL               | medium     |
| S3 Bucket Reference        | medium     |

## Limites de Escopo

- Somente JS files públicos — não tentar bypass de autenticação.
- Máximo 20 JS files por página para evitar timeout.
- Não usar secrets encontrados para acesso não autorizado.

## Correlação

- Secret encontrado + endpoint ativo → risco alto.
- AWS key em JS + s3scanner → verificar acesso a buckets.
- JWT em JS → alimentar jwt_analyzer para análise.
- Internal IP em JS → mapear infraestrutura interna.
