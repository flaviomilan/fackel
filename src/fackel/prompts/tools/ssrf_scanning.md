# Tool — SSRF Scanning

## Objetivo

Detectar vulnerabilidades de Server-Side Request Forgery (SSRF) que
permitem um atacante fazer o servidor alvo enviar requests para
recursos internos ou arbitrários.

## Ferramentas

| Ferramenta       | Propósito                                         |
|------------------|---------------------------------------------------|
| `ssrf_detect`    | Detecção via nuclei templates (ssrf, oast tags)   |
| `nuclei_scan`    | Com `-tags ssrf` para cobertura adicional         |
| `open_redirect_scan` | Open redirect → pode escalar para SSRF       |
| `ssti_scan`      | SSTI → frequentemente chained com SSRF            |

## Regras de Uso

1. **ssrf_detect em endpoints que aceitam URLs como parâmetros** —
   parâmetros como url=, redirect=, callback=, next=, file=, path=.
2. **Blind SSRF via OOB** — nuclei usa callbacks OAST para detectar
   blind SSRF (o servidor faz request para domínio controlado).
3. **Correlacionar com open redirect** — open redirect pode ser
   chained para SSRF bypass de whitelists.
4. **Verificar cloud metadata** — SSRF para 169.254.169.254 em
   ambientes cloud (AWS, GCP, Azure) é critical.

## Limites de Escopo

- Não tentar acessar recursos internos manualmente.
- Somente detecção — não exfiltrar dados via SSRF.
- Respeitar rate limiting do alvo.

## Estratégia de Fallback

| Cenário                    | Ação                                       |
|----------------------------|--------------------------------------------|
| WAF bloqueando callbacks   | Documentar WAF, tentar encoding alternativo|
| Sem parâmetros URL         | Usar crawling para descobrir endpoints     |
| nuclei sem findings        | Documentar como "não detectável por scan auto" |

## Normalização

- Tipo: blind_ssrf, full_read_ssrf, partial_ssrf.
- Severity: critical (full read/cloud metadata), high (blind SSRF), medium (partial).
- Template ID preservado para referência.
