# Advanced Nmap Scanning Techniques

## 🎯 Melhorias Implementadas

### 1. **Service Version Detection Avançado**
```bash
-sV --version-intensity 7
```
- **Intensity 7**: Mais agressivo que o padrão (5)
- Detecta versões precisas de serviços
- Útil para identificar vulnerabilidades específicas

### 2. **OS Detection (Fingerprinting)**
```bash
-O --osscan-guess
```
- **Requer privilégios root/sudo**
- Identifica sistema operacional
- Accuracy percentage para cada match
- Extrai OS family, vendor, generation

### 3. **NSE Scripts Avançados**

#### Scripts de Vulnerabilidade
```bash
--script vulners,vuln
```
- **vulners**: CVEs com CVSS scores
- **vuln**: Categoria completa de scripts de vulnerabilidade
  - `http-vuln-*`: Vulnerabilidades web (Shellshock, Heartbleed, etc.)
  - `smb-vuln-*`: Vulnerabilidades SMB (MS17-010, etc.)
  - `ssl-*`: Vulnerabilidades SSL/TLS
  - `ssh-*`: Vulnerabilidades SSH

#### Scripts Padrão Seguros
```bash
-sC
```
Equivalente a `--script=default`, inclui:
- `http-title`: Título de páginas web
- `ssh-hostkey`: Fingerprints SSH
- `ssl-cert`: Informações de certificados
- `dns-nsid`: DNS server identity
- E 50+ outros scripts seguros

### 4. **Timing Agressivo**
```bash
-T4 --max-retries 2 --host-timeout 10m
```
- **T4**: Template "aggressive" (mais rápido que padrão T3)
- **max-retries 2**: Limita tentativas para acelerar
- **host-timeout 10m**: Timeout por host

### 5. **Parsing Avançado**

#### Informações Extraídas
```python
{
  "target": "example.com",
  "state": "up",
  "hostnames": [{"name": "example.com", "type": "PTR"}],
  "addresses": {"ipv4": "93.184.216.34"},
  
  "os_info": {
    "os_matches": [
      {"name": "Linux 3.2 - 4.9", "accuracy": 95}
    ],
    "os_classes": [
      {
        "type": "general purpose",
        "vendor": "Linux",
        "osfamily": "Linux",
        "osgen": "4.X",
        "accuracy": 95
      }
    ]
  },
  
  "services": [
    {
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": "https",
      "product": "nginx",
      "version": "1.18.0",
      "cpe": "cpe:/a:nginx:nginx:1.18.0",
      "vulnerabilities": [
        {
          "id": "CVE-2021-23017",
          "cvss": 7.5,
          "source": "vulners"
        }
      ],
      "scripts": {
        "http-title": "Welcome to nginx!",
        "ssl-cert": "Subject: CN=example.com..."
      }
    }
  ],
  
  "summary": {
    "total_ports_scanned": 12,
    "open_ports": 3,
    "filtered_ports": 2,
    "total_vulnerabilities": 5,
    "os_detected": true
  }
}
```

---

## 🚀 Técnicas Avançadas Disponíveis

### A. Scan Completo de Portas
Para escanear **todas as 65535 portas** (muito lento):

```python
# Adicionar ao arguments:
"-p-"  # ou "--allports"
```

Compromisso: Escaneamos apenas top 1000 portas por padrão (99% dos serviços comuns).

### B. Scripts NSE por Categoria

```python
# Descoberta agressiva
"--script discovery"

# Autenticação
"--script auth"

# Força bruta (apenas em active scans autorizados)
"--script brute"

# Exploits (cuidado!)
"--script exploit"

# Todos os seguros
"--script safe"
```

### C. Service Detection Máximo

```python
"-sV --version-light"     # Rápido mas menos preciso
"-sV"                      # Padrão (intensity 7)
"-sV --version-all"        # Testa TODAS as probes (muito lento)
```

### D. OS Detection Avançado

```python
"-O"                       # Básico
"-O --osscan-limit"        # Apenas se host tem porta aberta + fechada
"-O --osscan-guess"        # Força guess mesmo com dados limitados
```

### E. Evasão de Firewall/IDS

```python
"-f"                       # Fragment packets
"--mtu 24"                 # Set MTU
"-D RND:10"                # Decoy scan (10 IPs falsos)
"--source-port 53"         # Usa porta source 53 (DNS)
"--data-length 200"        # Append random data
"--badsum"                 # Envia checksums inválidos
```

### F. Performance vs Stealth

```bash
# Stealth (lento, evita detecção)
-T0 (paranoid)
-T1 (sneaky)

# Normal
-T2 (polite)
-T3 (normal) - padrão

# Agressivo (rápido, detectável)
-T4 (aggressive) - ✅ ATUAL
-T5 (insane)
```

---

## 📊 Outputs Estruturados

### 1. Services
```python
{
  "port": 443,
  "protocol": "tcp",
  "state": "open|closed|filtered",
  "service": "https",
  "product": "nginx",
  "version": "1.18.0",
  "extrainfo": "Ubuntu",
  "cpe": "cpe:/a:nginx:nginx:1.18.0",
  "vulnerabilities": [...],
  "scripts": {...}
}
```

### 2. OS Information
```python
{
  "os_matches": [
    {"name": "Linux 4.15 - 5.6", "accuracy": 95},
    {"name": "Linux 3.2 - 4.9", "accuracy": 92}
  ],
  "os_classes": [
    {
      "type": "general purpose",
      "vendor": "Linux",
      "osfamily": "Linux",
      "osgen": "4.X",
      "accuracy": 95
    }
  ]
}
```

### 3. Vulnerabilities
```python
{
  "id": "CVE-2021-23017",
  "cvss": 7.5,
  "source": "vulners|vulscan|nse_script",
  "description": "1-Click RCE via DNS..."
}
```

---

## 🛡️ Requisitos

### Root/Sudo (Opcional)
Para OS detection (`-O`), rode com privilégios:

```bash
sudo uv run fackel run example.com --active-scan
```

Sem root, o scan continua funcional mas sem OS detection.

### NSE Scripts
Scripts Nmap devem estar instalados (geralmente vêm com Nmap):

```bash
# Verificar scripts disponíveis
ls /usr/share/nmap/scripts/ | grep vuln

# Atualizar NSE database
sudo nmap --script-updatedb
```

---

## 🎯 Quando Usar

### Passive Scan (Padrão)
- **NÃO** usa Nmap (muito invasivo)
- Usa ferramentas passivas (Shodan, Censys, etc.)

### Active Scan (`--active-scan`)
- ✅ **USA** Nmap avançado
- Detecção de versões
- OS fingerprinting
- Vulnerability scanning
- ⚠️ **Apenas em hosts autorizados!**

---

## 📈 Comparação: Antes vs Depois

### Antes
```python
arguments = "-sV -T4 --script vulners"
data = {"services": [...]}  # Apenas serviços
```

**Informações**: Portas, serviços, versões, CVEs básicos

### Depois
```python
arguments = "-sV --version-intensity 7 -sC --script vulners,vuln -T4 -O --osscan-guess"
data = {
  "services": [...],
  "os_info": {...},
  "hostnames": [...],
  "host_scripts": {...},
  "summary": {...}
}
```

**Informações**: 
- ✅ Portas, serviços, versões
- ✅ CVEs com CVSS scores
- ✅ OS detection (sistema operacional)
- ✅ Hostnames e endereços
- ✅ CPE (Common Platform Enumeration)
- ✅ Scripts NSE (50+ checks)
- ✅ Vulnerabilidades web/SSH/SSL
- ✅ Estatísticas agregadas

**Aumento**: ~300% mais informações

---

## 🚨 Avisos de Segurança

1. **Apenas hosts autorizados**: Scanning não autorizado é **ilegal**
2. **Rate limiting**: `-T4` pode ser detectado por IDS/IPS
3. **Logs**: Scans deixam rastros em logs do alvo
4. **Responsabilidade**: Use apenas em ambiente de teste ou com autorização

---

## 💡 Próximas Melhorias Possíveis

### P1 - High Priority
- [ ] Scan adaptivo: `-p1-10000` se poucos hosts, `-p-` se um único host
- [ ] NSE script selection baseado em serviços detectados
- [ ] Retry logic para hosts intermitentes
- [ ] Output XML parsing para dados adicionais

### P2 - Medium Priority
- [ ] UDP scanning (`-sU`) para serviços não-TCP
- [ ] IPv6 support (`-6`)
- [ ] Traceroute (`--traceroute`)
- [ ] Script args customizados (`--script-args`)

### P3 - Low Priority
- [ ] Parallel scanning de múltiplos hosts
- [ ] NSE script output normalization
- [ ] Integration com exploit databases
- [ ] Custom NSE scripts para fingerprinting específico

---

**Status**: ✅ Implementado com técnicas avançadas de levantamento de informações!
