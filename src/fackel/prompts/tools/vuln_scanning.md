# Tool — Vulnerability Scanning

## Objetivo

Identificar vulnerabilidades conhecidas em serviços, aplicações web e
configurações do alvo usando scanners automatizados.

## Ferramentas

| Ferramenta                | Propósito                                                 |
|---------------------------|-----------------------------------------------------------|
| `nuclei_scan`             | Templates de vulnerabilidades (CVEs, misconfigs)          |
| `testssl_scan`            | Análise de configuração TLS/SSL                           |
| `security_headers_audit`  | Auditoria de headers de segurança HTTP (CSP, HSTS, etc.) |
| `sqlmap_scan`             | Detecção automatizada de SQL Injection                    |
| `ssrf_detect`             | Detecção de Server-Side Request Forgery via nuclei        |
| `open_redirect_scan`      | Detecção de Open Redirect via nuclei                      |
| `ssti_scan`               | Detecção de Server-Side Template Injection via nuclei     |
| `jwt_analyzer`            | Análise de segurança de JWT tokens                        |

## Regras de Uso

1. **nuclei é o scanner principal** — executar com templates relevantes
   para as tecnologias detectadas.
2. **Templates seletivos** — usar tags baseadas no fingerprinting:
   - WordPress detectado → `-tags wordpress`
   - Apache → `-tags apache`
   - GraphQL detectado → `-tags graphql`
   - Genérico → `-tags cve,misconfig,exposure`
3. **Scans especializados via nuclei** — para coberturas específicas:
   - SQLi suspect → `ssrf_detect` ou `nuclei_scan -tags sqli`
   - Redirect params detectados → `open_redirect_scan`
   - Template engine detectado → `ssti_scan -tags ssti`
   - SSRF suspect → `ssrf_detect -tags ssrf`
4. **testssl em hosts HTTPS** — verificar cipher suites, protocolos,
   certificados, vulnerabilidades TLS.
5. **security_headers_audit em todos os hosts web** — análise pura HTTP
   sem dependência de binários externos.
6. **sqlmap em endpoints com parâmetros** — usar `--batch --level=1
   --risk=1` para automação segura. Ferramenta ativa: requer aprovação.
7. **jwt_analyzer quando JWT detectado** — decodificar, verificar alg:none,
   claims expirados, segredos fracos. Ferramenta passiva sem binários.
8. **Categorizar severidade** — critical, high, medium, low, info.
9. **Evidência obrigatória** — cada finding deve ter prova (request/response).

## Limites de Escopo

- Somente hosts autorizados.
- Não usar templates de exploit/RCE sem autorização explícita.
- Rate limit: máximo 10 requests/segundo por host.
- Não executar fuzzing extensivo sem justificativa.
- sqlmap **somente** com `--batch` e `--level ≤ 2` em modo automatizado.

## Estratégia de Fallback

| Cenário                    | Ação                                       |
|----------------------------|--------------------------------------------|
| WAF bloqueando nuclei      | Reduzir rate, documentar WAF               |
| Templates timeout          | Retry com timeout maior ou tags específicas |
| Muitos findings (>100)     | Filtrar por severity >= medium             |
| testssl timeout            | Tentar com checks='protocols,vulnerabilities' |
| testssl sem resultado      | Retry com fast=False e openssl_timeout=20  |
| nuclei vazio               | Retry com tags da tecnologia detectada     |
| False positive provável    | Marcar como "needs verification"           |

## Estrutura de Output

```json
{
  "tool": "nuclei_scan",
  "target": "https://example.com",
  "data": {
    "findings": [
      {
        "template_id": "CVE-2024-1234",
        "name": "WordPress Plugin RCE",
        "severity": "critical",
        "url": "https://example.com/wp-content/plugins/vuln/",
        "matched_at": "https://example.com/wp-content/plugins/vuln/readme.txt",
        "evidence": "Version: 2.3.1 (vulnerable < 2.5.0)",
        "tags": ["cve", "wordpress", "rce"]
      }
    ],
    "total_findings": 12,
    "by_severity": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 3
    }
  }
}
```

## Normalização

- CVE IDs no formato CVE-YYYY-NNNNN.
- Severity padronizado: critical, high, medium, low, info.
- URLs completas (não relativas).
- Tags preservadas para cruzamento.

## Anomalias

- **CVE critical confirmado** → prioridade máxima no relatório.
- **TLS 1.0/1.1 habilitado** → compliance issue (PCI DSS).
- **Self-signed cert em produção** → trust issue, potencial MitM.
- **Cipher suites fracas** (RC4, DES, NULL) → risco de interceptação.
- **Múltiplas vulns no mesmo componente** → sistema sem patching.
- **Info disclosure** (stack traces, version headers) → facilita exploração.
