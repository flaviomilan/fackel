# Reporting — Relatório de Compliance

## Objetivo

Mapear achados contra frameworks de compliance relevantes (OWASP Top 10,
PCI DSS, LGPD/GDPR, ISO 27001) identificando gaps de conformidade.

## Inputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `classified_findings`| `list[dict]` | Achados com severidade e tipo           |
| `entity_profiles`    | `list[dict]` | Perfis de entidades                     |
| `applicable_frameworks`| `list[str]`| Frameworks aplicáveis                   |
| `${user_context}`    | `string`     | Contexto (indústria, regulação)         |

## Outputs

| Campo                | Tipo         | Descrição                               |
|----------------------|--------------|-----------------------------------------|
| `compliance_report`  | `string`     | Relatório de compliance (Markdown)      |
| `framework_mapping`  | `dict`       | Achados mapeados por framework          |
| `compliance_gaps`    | `list[dict]` | Gaps de conformidade identificados      |
| `compliance_score`   | `dict`       | Score por framework (0-100%)            |

## Regras

1. **Frameworks suportados**:
   - **OWASP Top 10 (2021)**: A01-Broken Access Control → A10-SSRF.
   - **PCI DSS v4.0**: Requisitos 1-12 (comid scope).
   - **LGPD/GDPR**: Proteção de dados pessoais.
   - **ISO 27001**: Controles do Anexo A.
   - **CIS Controls v8**: Safeguards aplicáveis.
2. **Mapeamento preciso** — cada achado mapeado para CWE → OWASP → framework.
3. **Não assumir compliance** — ausência de achado não implica conformidade.
4. **Documentar limitações** — assessment externo não verifica controles
   organizacionais internos.
5. **Score conservador** — na dúvida, marcar como "não verificável".

## Critérios de Qualidade

- Mapeamento referenciando requisitos específicos do framework.
- Gaps com referência cruzada a achados.
- Score reflete somente controles verificáveis externamente.
- Limitações documentadas explicitamente.

## Template

```markdown
# Relatório de Compliance

## Frameworks Aplicáveis
[Lista de frameworks e justificativa de aplicabilidade]

## OWASP Top 10 (2021)

| Categoria           | Achados Relacionados | Status        |
|---------------------|---------------------|---------------|
| A01 - Broken Access | F-02, F-15          | NÃO CONFORME  |
| A02 - Crypto Fail   | F-08                | PARCIAL       |
| A03 - Injection      | —                   | CONFORME*     |
| ...                  |                     |               |

*Conforme = nenhum achado, mas verificação limitada ao escopo externo.

## PCI DSS v4.0 (se aplicável)

| Requisito | Descrição              | Achados | Status       |
|-----------|------------------------|---------|--------------|
| 6.2       | Secure dev practices   | F-03    | NÃO CONFORME |
| ...       |                        |         |              |

## Gaps de Conformidade
1. [Gap]: [achado(s)] → [requisito] → [remediação]

## Limitações do Assessment
- Assessment externo não verifica: [lista de controles internos]
- Score reflete somente superfície externamente visível
```
