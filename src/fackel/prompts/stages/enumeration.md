# Stage — Enumeração

## Objetivo

Expandir a superfície de ataque conhecida a partir dos dados do recon
inicial: descobrir hosts adicionais, portas abertas, serviços e versões.

## Inputs

| Campo              | Tipo       | Obrigatório | Descrição                               |
|--------------------|------------|-------------|-----------------------------------------|
| target             | string     | sim         | Domínio ou IP principal                 |
| discovered_ips     | list[str]  | sim         | IPs do recon inicial                    |
| subdomains         | list[str]  | sim         | Subdomínios descobertos                 |
| ip_classifications | list[dict] | sim         | CDN/cloud/direct_host por IP            |
| user_context       | string     | não         | Contexto adicional                      |

## Outputs

| Campo            | Tipo        | Descrição                                  |
|------------------|-------------|--------------------------------------------|
| open_ports       | list[dict]  | IP, porta, estado, serviço, versão         |
| services         | list[dict]  | Serviço + versão exata por IP:porta        |
| cdn_filtered_ips | list[str]   | IPs que foram skippados (atrás de CDN)     |

## Regras

1. **Priorizar IPs únicos** — não escanear 100 subdomínios que apontam para
   os mesmos 2-3 IPs.  Escanear os IPs, depois verificar apenas subdomínios
   em infra diferente.
2. **Naabu primeiro, nmap depois** — naabu para discovery rápido, nmap com
   `-sV -sC` nos ports descobertos para fingerprint.
3. **CDN awareness** — IPs classificados como `cdn` recebem `skip_cdn=true`.
4. **Versões obrigatórias** — usar `scan_type="default"` (nunca "quick") para
   capturar server banners, TLS versions, SSH algorithms.
5. **Paralelismo** — todos os naabu calls em um batch; todos os nmap calls em
   outro batch.
6. **Se `user_context` fornecido** — adaptar profundidade (ex: "foco em web"
   → priorizar portas 80/443/8080/8443).

## Critérios de Qualidade

| Critério                     | Mínimo Esperado                          |
|------------------------------|------------------------------------------|
| Cobertura de IPs             | 100% dos IPs direct_host escaneados      |
| Service version detection    | nmap `-sV` executado em todos os ports   |
| Falhas documentadas          | Cada timeout/erro registrado             |
| NSE script findings          | http-title, ssl-cert, ssh-hostkey        |

## Template

```text
Fase de ENUMERAÇÃO para: ${target}

IPs a escanear: ${discovered_ips}
Subdomínios: ${subdomains_count} (${unique_ips_count} IPs únicos)

${user_context ? "Contexto do operador: " + user_context : ""}

Procedimento:
1. naabu_scan em paralelo para todos os IPs (top_ports="1000")
2. nmap_port_scan em paralelo para todos os IPs com ports do naabu
   - scan_type="default" para -sV -sC
   - Se naabu não encontrou ports → nmap com skip_host_discovery=true
3. Para subdomínios em infra diferente dos IPs principais:
   - httpx_scan + naabu_scan em batch

Formato de saída: tabela Port | State | Service | Version | Notes por IP.
```
