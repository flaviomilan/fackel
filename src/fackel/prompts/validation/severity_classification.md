# Validation — Classificação de Severidade

## Objetivo

Atribuir severidade padronizada a cada achado validado, usando critérios
objetivos baseados em impacto, exploitabilidade e contexto.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `confirmed_findings` | `list[dict]` | Achados confirmados (pós-FP filter)     |
| `target_context`     | `dict`       | Contexto do alvo (dados sensíveis, exposição) |
| `cvss_data`          | `dict`       | CVSS scores quando disponíveis          |
| `${user_context}`    | `string`     | Contexto operacional (opcional)         |

## Outputs

| Campo                    | Tipo         | Descrição                            |
|--------------------------|--------------|--------------------------------------|
| `classified_findings`    | `list[dict]` | Achados com severidade atribuída     |
| `severity_distribution`  | `dict`       | Contagem por severidade              |
| `critical_count`         | `int`        | Achados critical para destaque       |

## Regras

1. **Escala de severidade**: critical, high, medium, low, info.
2. **Critérios por nível**:
   - **Critical**: RCE, SQLi com data access, credential exposure active,
     admin panel sem auth. CVSS >= 9.0.
   - **High**: XSS stored, IDOR, privilege escalation, S3 bucket
     public read. CVSS 7.0-8.9.
   - **Medium**: XSS reflected, CORS misconfiguration, information
     disclosure significativo. CVSS 4.0-6.9.
   - **Low**: Missing headers, minor info disclosure, outdated but
     not vulnerable. CVSS 0.1-3.9.
   - **Info**: Technology detection, DNS records, infrastructure mapping.
3. **CVSS base score prevalece** quando disponível (fonte: NVD).
4. **Contexto pode elevar** — XSS reflected em app bancário pode ser high
   em vez de medium.
5. **Não inflar severidade** — sem evidência de impacto, classificar pelo
   CVSS base.
6. **Consistência** — mesmo tipo de vuln em hosts diferentes recebe mesma
   severidade base.

## Critérios de Qualidade

- Todo achado com severidade atribuída.
- Critério usado documentado por achado.
- CVSS referenciado quando aplicável.
- Distribuição de severidade razoável (não tudo é critical).
- Contexto aplicado consistentemente.

## Template

```
CLASSIFICAÇÃO DE SEVERIDADE
=============================

Para cada achado confirmado:
1. Verificar se CVSS base score disponível
2. Se sim: usar CVSS como base
3. Se não: classificar por critérios objetivos:
   - Impacto (C/I/A): confidencialidade, integridade, disponibilidade
   - Exploitabilidade: remoto? autenticação necessária? complexidade?
   - Contexto: dados sensíveis? exposição pública? 
4. Atribuir severidade e documentar critério

| Achado            | CVSS  | Impacto | Exploit. | Contexto | Severidade |
|-------------------|-------|---------|----------|----------|------------|
| CVE-2024-1234     | 9.8   | C/I/A   | remoto   | produção | critical   |
| XSS /search       | —     | C       | remoto   | público  | medium     |
| Missing X-Frame   | —     | I       | complexo | interno  | low        |

Distribuição: critical(1) high(3) medium(5) low(8) info(12)
```
