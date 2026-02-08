# Fackel – Arquitetura Revisada

## Objetivos
- Coletar OSINT de forma ética, priorizando passivo por padrão.
- Correlacionar hosts/serviços/CVEs e produzir relatório explicável.
- Habilitar scoring e rastreabilidade via dados estruturados persistidos.

## Componentes
- **Agent Layer**: `OsintProcessor` monta agente LangChain com tools filtradas por capacidades (chaves de API). Define limites (`max_iterations`, `max_execution_time`) e retorna `intermediate_steps` para ingestão estruturada.
- **Capabilities**: `src/capabilities.py` detecta variáveis de ambiente requeridas por cada tool, habilita/desabilita dinamicamente e injeta resumo no prompt.
- **Tools**: Principais tools agora retornam payloads estruturados (`whois`, `shodan`, `virustotal`, `probe_host`, `nmap`).
- **Store**: `src/store.py` + `src/models.py` armazenam `DomainReport` (hosts, serviços, CVEs, evidências). Persistência em JSON (`store.save_json`).
- **Normalizers**: `src/normalizers.py` converte outputs das tools em estrutura, com fallback para parsing textual e adição de evidências cruas.
- **CLI**: `src/main.py` invoca `OsintProcessor`, opcionalmente exporta HTML e sempre salva JSON estruturado.

## Fluxo de Dados
1. Usuário chama `main.py dominio [--active-scan] [--output x.html]`.
2. `OsintProcessor` detecta capabilities e monta tools disponíveis.
3. Agente roda com limites, coleta `intermediate_steps`.
4. Cada step passa por `normalize_and_store`, alimentando `StructuredStore`.
5. Markdown final vai para stdout/HTML; JSON estruturado é salvo para correlação e scoring futuros.

## Evoluções Planejadas
- Scoring de risco baseado em CVSS + exposição por host.
- Deduplicação avançada de hosts/subdomínios e fusão de evidências.
- Integração com LangFlow para orquestração visual e deploy.
- Suporte a storage SQLite para consultas incrementais e histórico.
