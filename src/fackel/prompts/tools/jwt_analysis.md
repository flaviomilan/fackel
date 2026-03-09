# Tool — JWT Analysis

## Objetivo

Analisar tokens JWT para identificar fraquezas de segurança:
algoritmo none, segredos fracos, claims ausentes, tokens expirados,
e headers perigosos (jku, jwk, kid injection).

## Ferramentas

| Ferramenta      | Propósito                                          |
|-----------------|----------------------------------------------------|
| `jwt_analyzer`  | Decodificação e análise de segurança de JWT        |

## Regras de Uso

1. **Usar quando JWT detectado** — em cookies, headers Authorization,
   respostas de API, ou JavaScript inline.
2. **Análise passiva** — não requer requests adicionais ao alvo.
3. **Verificar alg:none** — vulnerabilidade critical que permite forjar tokens.
4. **Verificar segredos fracos** — brute-force contra wordlist comum.
5. **Claims obrigatórias** — exp, iat, iss devem estar presentes.

## Priorização de Findings

| Finding                  | Severity   |
|--------------------------|------------|
| alg:none                 | critical   |
| Weak secret detected     | critical   |
| jku/jwk in header        | high       |
| kid path traversal       | high       |
| Missing exp claim        | high       |
| Expired token            | medium     |
| Symmetric alg (HS256)    | info       |
| Missing iat/iss          | low        |

## Limites de Escopo

- Somente análise de tokens fornecidos — não interceptar tráfego.
- Não tentar usar tokens modificados contra o alvo.
- Não exfiltrar dados via tokens.

## Correlação

- JWT com alg:none + API sem rate limit → risco máximo.
- JWT com segredo fraco + missing exp → acesso permanente.
- JWT em JavaScript inline → combinado com js_secret_scan.
