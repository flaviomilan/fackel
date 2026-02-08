# Fackel – Arquitetura Revisada

## Objetivos
- Coletar OSINT de forma ética, priorizando passivo por padrão.
- Correlacionar hosts/serviços/CVEs e produzir relatório explicável.
- Habilitar scoring e rastreabilidade via dados estruturados persistidos.

## Componentes
- **Agent Layer**: `LangGraphAgent` (`src/fackel/agents/graph_agent.py`) compila um `StateGraph` com nós de planejamento e execução. Executa `TOOL_REGISTRY`, normaliza saídas e atualiza estado/confiança.
- **Capabilities**: `src/capabilities.py` detecta variáveis de ambiente requeridas por cada tool e define quais entram no plano inicial.
- **Tools**: Registry em `src/collectors/collectors.py` expõe ferramentas passivas/ativas, incluindo payloads estruturados para `whois`, `shodan`, `virustotal`, `probe_host` e `nmap`.
- **Store**: `src/fackel/core/store.py` + `src/fackel/core/models.py` (Pydantic) guardam `DomainReport` (hosts, serviços, CVEs, pessoas, evidências). Persistência em JSON (`save_json`).
- **Normalizers**: `src/fackel/core/normalizers/builtin.py` padroniza saídas por tool; registry em `src/fackel/core/normalizers/registry.py` aplica o normalizador correto.
- **Reporting**: `src/fackel/reporting/renderer.py` calcula score por host/domínio e gera resumo Markdown estruturado.
- **CLI**: `src/cli/main.py` (Typer) é o entrypoint `fackel run dominio [--active-scan] [--output]`, grava Markdown/JSON e imprime o resumo.
- **Tracing (opcional)**: Langfuse é inicializado pelo agente quando as variáveis `LANGFUSE_*` estão presentes.

## Fluxo de Dados
1. Usuário executa `fackel run dominio [--active-scan] [--output report.md]`.
2. CLI instancia `LangGraphAgent`, que detecta capabilities e monta plano inicial (tools passivas + ativas se habilitadas).
3. O `StateGraph` percorre o plano: para cada tool, executa, normaliza a saída e acumula no `StructuredStore`.
4. Ao final, `render_structured_summary` gera o Markdown de saída; o `StructuredStore` pode ser salvo em JSON para correlação futura.
5. Se Langfuse estiver configurado, cada tool e o resumo final são enviados como spans/trace.

## Evoluções Planejadas
- Scoring de risco aprimorado baseado em CVSS + exposição por host.
- Deduplicação avançada de hosts/subdomínios e fusão de evidências.
- Suporte a storage SQLite para consultas incrementais e histórico.
