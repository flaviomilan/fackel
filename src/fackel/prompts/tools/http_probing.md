# Tool — HTTP Probing

## Objetivo

Identificar tecnologias web, headers de servidor, WAF/CDN, redirects
e status codes para cada host na superfície de ataque.

## Ferramentas

| Ferramenta      | Propósito                                          |
|-----------------|----------------------------------------------------|
| `httpx_scan`    | Probing HTTP rápido — tech, títulos, redirects     |
| `whatweb_scan`  | Fingerprint profundo — CMS, frameworks, libs, versões |
| `wafw00f_detect`| Identificação de WAF/IPS                           |

## Regras de Uso

1. **httpx é obrigatório** — executar em todo domínio/IP com porta web.
2. **whatweb complementa httpx** — detecta CMS versions, jQuery, analytics
   que httpx não captura.  Executar nos hosts principais.
3. **wafw00f** — executar no domínio principal para identificar WAF.
4. **Paralelismo** — httpx, whatweb e wafw00f são independentes, executar
   em batch.

## Limites de Escopo

- Somente hosts autorizados e portas conhecidas (80, 443, 8080, 8443).
- Não seguir redirects para domínios fora do escopo.
- Respeitar robots.txt como indicador (documentar, não bloquear).

## Estratégia de Fallback

| Cenário              | Ação                                            |
|----------------------|-------------------------------------------------|
| Connection refused   | Host não serve HTTP — documentar                |
| TLS error            | Tentar HTTP-only, documentar erro TLS           |
| WAF blocking         | Documentar WAF, notar impacto nos resultados    |
| Timeout              | Tentar com timeout maior, documentar se persistir|

## Estrutura de Output

```json
{
  "tool": "httpx_scan",
  "target": "<host>",
  "data": {
    "url": "https://example.com",
    "status_code": 200,
    "title": "Site Title",
    "server": "nginx/1.24",
    "technologies": ["WordPress 6.4", "PHP 8.2"],
    "cdn": "cloudflare",
    "waf": "cloudflare",
    "redirect_chain": ["http://example.com → https://example.com"]
  }
}
```

## Normalização

- URLs normalizadas (trailing slash consistente).
- Server headers preservados verbatim (case-sensitive).
- Tecnologias com versão quando disponível.

## Anomalias

- **Redirect para domínio externo** → possível phishing ou migração.
- **Server header ausente** → hardening ou proxy reverso.
- **Múltiplos WAFs** → configuração complexa, potenciais bypasses.
- **HTTP 403 em tudo** → WAF agressivo ou IP bloqueado.
- **Título inesperado** (ex: "Parking page") → domínio pode ter expirado.
