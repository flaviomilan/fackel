# Tool — Port Scanning

## Objetivo

Identificar portas abertas, serviços ativos e versões de software em
hosts do alvo para mapeamento da superfície de ataque de rede.

## Ferramentas

| Ferramenta      | Propósito                                         |
|-----------------|---------------------------------------------------|
| `naabu_scan`    | Scan rápido de portas (SYN scan, top-1000)        |
| `nmap_port_scan`| Scan profundo — service detection, versões, scripts|

## Regras de Uso

1. **naabu primeiro** — scan rápido para identificar portas abertas.
2. **nmap depois** — scan detalhado (-sV -sC) somente nas portas que
   naabu encontrou.
3. **Nunca nmap full scan (-p-)** em todos os hosts — usar naabu para
   filtrar primeiro.
4. **Service version obrigatório** — `nmap -sV` sempre, versão é
   essencial para CVE matching.
5. **Scripts NSE seletivos** — usar `--script=default,vuln` apenas em
   hosts prioritários.

## Limites de Escopo

- Somente IPs/hosts autorizados.
- Respeitar rate limits configurados.
- Não executar exploit scripts (--script=exploit).
- UDP scan apenas quando justificado (DNS, SNMP, NTP).

## Estratégia de Fallback

| Cenário                  | Ação                                        |
|--------------------------|---------------------------------------------|
| Host filtrado/firewalled | Documentar como "filtered", não insistir    |
| naabu timeout            | Reduzir rate, tentar top-100 ports          |
| nmap -sV sem resultado   | Tentar com --version-intensity 9            |
| IDS/IPS detectado        | Reduzir agressividade, documentar           |

## Estrutura de Output

```json
{
  "tool": "nmap_port_scan",
  "target": "203.0.113.10",
  "data": {
    "ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 8.9p1",
        "product": "OpenSSH",
        "extra_info": "Ubuntu Linux"
      },
      {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "service": "https",
        "version": "nginx 1.24.0",
        "product": "nginx"
      }
    ],
    "os_detection": "Linux 5.x",
    "total_open": 5,
    "scan_type": "SYN",
    "scan_duration_seconds": 45
  }
}
```

## Normalização

- Portas como inteiros (não strings).
- Protocolos lowercase (tcp, udp).
- State: open, closed, filtered (vocabulário nmap).
- Service names padronizados (http, https, ssh, não HTTP ou SSH).

## Anomalias

- **Portas altas abertas (>10000)** → possível backdoor ou serviço custom.
- **SSH em porta não-padrão** → possível hardening ou evasão.
- **Serviços desatualizados** → verificar CVEs imediatamente.
- **Múltiplas portas web** (80, 443, 8080, 8443) → aplicações múltiplas,
  cada uma é superfície distinta.
- **Portas de banco de dados expostas** (3306, 5432, 27017) → risco
  crítico se acessível externamente.
