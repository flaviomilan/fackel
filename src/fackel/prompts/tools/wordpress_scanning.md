# Tool — WordPress Scanning

## Objetivo

Identificar vulnerabilidades específicas de WordPress: plugins
desatualizados, temas vulneráveis, enumeração de usuários, configurações
inseguras.

## Ferramentas

| Ferramenta       | Propósito                                        |
|------------------|--------------------------------------------------|
| `wpscan_scan`    | Scanner especializado WordPress — plugins, temas, users |

## Regras de Uso

1. **Executar somente quando WordPress detectado** — confirmar via
   fingerprinting (whatweb/httpx) antes de executar.
2. **Enumeração completa**: plugins (-e ap), temas (-e at), usuários (-e u).
3. **Versões de plugins são críticas** — match direto com CVE databases.
4. **API token WPScan** — se disponível, usar para dados de vulnerabilidade
   atualizados do WPVulnDB.
5. **Documentar TUDO** — mesmo plugins sem CVE conhecida são superfície.

## Limites de Escopo

- Somente sites WordPress no escopo.
- Não tentar brute-force de senhas.
- Não explorar vulnerabilidades encontradas.
- Rate limit adequado para não derrubar o site.

## Estratégia de Fallback

| Cenário                    | Ação                                       |
|----------------------------|--------------------------------------------|
| WAF bloqueando WPScan      | Stealth mode (--random-user-agent)        |
| Sem API token              | Executar sem — menos dados de CVE         |
| WordPress muito customizado| Enumerar manualmente via /wp-content/      |
| Timeout                    | Reduzir escopo a plugins + version only   |

## Estrutura de Output

```json
{
  "tool": "wpscan_scan",
  "target": "https://example.com",
  "data": {
    "wordpress_version": "6.4.2",
    "plugins": [
      {
        "name": "contact-form-7",
        "version": "5.8",
        "vulnerabilities": [],
        "outdated": false
      },
      {
        "name": "elementor",
        "version": "3.18",
        "vulnerabilities": ["CVE-2024-XXXX"],
        "outdated": true
      }
    ],
    "themes": [{"name": "twentytwentyfour", "version": "1.0"}],
    "users": ["admin", "editor1"],
    "total_plugins": 12,
    "vulnerable_plugins": 2
  }
}
```

## Normalização

- Plugin/theme names em slug format (lowercase, hyphens).
- CVEs no formato padrão.
- Versões em semver.

## Anomalias

- **Plugin com CVE known** → prioridade alta, especialmente RCE/SQLi.
- **Versão WordPress desatualizada** → múltiplos CVEs potenciais.
- **User "admin" existe** → brute-force target comum.
- **XML-RPC habilitado** → amplificação de brute-force.
- **Debug mode ativo** → information disclosure (wp-config.php).
