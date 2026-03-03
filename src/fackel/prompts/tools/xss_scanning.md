# Tool — XSS & CORS Scanning

## Objetivo

Detectar vulnerabilidades de Cross-Site Scripting (XSS) e CORS
misconfiguration em aplicações web do alvo.

## Ferramentas

| Ferramenta      | Propósito                                          |
|-----------------|----------------------------------------------------|
| `dalfox_scan`   | Scanner XSS avançado — reflected, stored, DOM-based|
| `corsy_scan`    | Detecção de CORS misconfiguration                  |

## Regras de Uso

1. **dalfox em endpoints com parâmetros** — extrair URLs do GAU/katana
   e alimentar dalfox.
2. **corsy em todos os hosts web** — CORS misconfiguration é comum e
   impactante.
3. **Paramspider + dalfox** — usar paramspider para descobrir parâmetros,
   depois dalfox para testar.
4. **Confirmar findings** — XSS requer evidência (payload + response).
5. **DOM XSS** — dalfox testa automaticamente, mas verificar sources/sinks.

## Limites de Escopo

- Somente endpoints autorizados.
- Não persistir payloads em stored XSS (apenas confirmar refletido).
- Rate limit: respeitar WAF/rate limiting do alvo.
- Não testar em formulários de pagamento ou áreas sensíveis sem
  autorização explícita.

## Estratégia de Fallback

| Cenário                   | Ação                                       |
|---------------------------|--------------------------------------------|
| WAF bloqueando payloads   | Tentar encoding alternativo, documentar WAF|
| Sem parâmetros encontrados| Usar crawling mais profundo                |
| dalfox timeout            | Reduzir scope a top endpoints              |
| corsy sem findings        | Documentar CORS como configurado corretamente|

## Estrutura de Output

```json
{
  "tool": "dalfox_scan",
  "target": "https://example.com/search?q=test",
  "data": {
    "findings": [
      {
        "type": "reflected_xss",
        "url": "https://example.com/search?q=<script>alert(1)</script>",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "Payload reflected in response body without encoding",
        "severity": "high",
        "waf_bypassed": false
      }
    ],
    "total_findings": 2,
    "endpoints_tested": 45
  }
}
```

## Normalização

- Tipo padronizado: reflected_xss, stored_xss, dom_xss, cors_misconfiguration.
- Payload preservado verbatim.
- Severity: critical (stored XSS w/ auth bypass), high (reflected XSS),
  medium (DOM XSS), low (CORS informational).

## Anomalias

- **Reflected XSS sem WAF** → fácil de explorar, prioridade alta.
- **CORS com origin: *  + credentials** → risco máximo, dados sensíveis
  acessíveis cross-origin.
- **Múltiplos parâmetros vulneráveis** → falta de sanitização sistêmica.
- **DOM XSS em JS de terceiros** → supply chain risk.
- **WAF bypass encontrado** → WAF mal configurado, falsa sensação de segurança.
