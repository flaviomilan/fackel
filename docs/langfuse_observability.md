# Guia Completo de Observabilidade com Langfuse

Este documento descreve como o Fackel usa todos os recursos do Langfuse para monitoramento completo de aplicações LLM.

## 📊 Overview do Sistema

O Fackel implementa observabilidade de ponta a ponta usando **todos os principais recursos do Langfuse**:

| Recurso | Status | Uso |
|---------|--------|-----|
| ✅ **Traces** | Implementado | Um trace por scan completo |
| ✅ **Spans** | Implementado | Tool executions, LLM calls, embeddings |
| ✅ **Scores** | Implementado | Quality, cost, latency, success, cache efficiency |
| ✅ **Tags** | Implementado | Security, recon, active_scan, findings |
| ✅ **Metadata** | Implementado | Domain, tools, models, costs, errors |
| ✅ **Token Tracking** | Implementado | Input/output tokens + cost calculation |
| ✅ **Cost Tracking** | Implementado | Per-model pricing ($0.15/$0.60/1M for GPT-4o-mini) |
| ✅ **Session Grouping** | Implementado | Group multiple scans by user/project |
| ✅ **Error Tracking** | Implementado | Automatic error capture with scores |
| ✅ **Cache Tracking** | Implementado | Redis cache hits/misses for embeddings |

---

## 🚀 Quick Start

### 1. Configuração

Configure as variáveis de ambiente no `.env`:

```bash
# Langfuse Configuration
LANGFUSE_PUBLIC_KEY="pk-lf-..."
LANGFUSE_SECRET_KEY="sk-lf-..."
LANGFUSE_HOST="http://localhost:3000"

# Optional
LANGFUSE_USER_ID="my_team"
LANGFUSE_TRACING_ENVIRONMENT="production"  # ou "staging", "local"
LANGFUSE_RELEASE="v1.2.3"
```

### 2. Verificar Conexão

```bash
# Teste a conexão
python -c "from fackel.core.observability import get_observability; obs = get_observability(); print('✓ Langfuse enabled' if obs.enabled else '✗ Langfuse disabled')"
```

### 3. Executar Scan com Monitoramento

```bash
uv run fackel run example.com
```

### 4. Visualizar no Dashboard

Acesse http://localhost:3000 e veja:
- **Traces**: Lista de todos os scans
- **Sessions**: Scans agrupados por domínio
- **Scores**: Métricas de qualidade/custo/latência
- **Analytics**: Custos totais, token usage, performance

---

## 🏗️ Arquitetura de Observabilidade

### Hierarquia de Traces

```
fackel_scan (Trace)
├── tool_execution (Span) - whois_lookup
│   └── success: 1.0, latency: 0.8
├── tool_execution (Span) - dns_lookup
│   └── success: 1.0, latency: 0.9
├── llm_call (Span) - incremental_analysis.nuclei
│   ├── input_tokens: 4521
│   ├── output_tokens: 387
│   ├── cost_usd: 0.0093
│   └── cost_efficiency: 1.0
├── embedding_call (Span) - playbook_query
│   ├── cached: true
│   └── cache_hit: 1.0
└── llm_call (Span) - final_report
    ├── input_tokens: 12044
    ├── output_tokens: 1523
    ├── cost_usd: 0.0238
    └── cost_efficiency: 0.5

Trace Scores:
├── findings_count: 14
├── critical_findings: 3
├── scan_coverage: 0.92
└── overall_quality: 0.85
```

---

## 📈 Recursos Implementados

### 1. Traces Automáticos

Cada execução de scan cria um trace com:

```python
# Automaticamente criado em LangGraphAgent.run()
with observability.trace_scan(
    domain="example.com",
    active_scan=True,
    metadata={"mode": "sync"},
):
    # Todas as operações dentro deste contexto são rastreadas
    pass
```

**Metadados incluídos**:
- `domain`: Alvo do scan
- `active_scan`: bool
- `environment`: production/staging/local
- `session_id`: Agrupa múltiplos scans
- `release`: Versão do código

**Tags automáticas**:
- `security`, `recon`: Sempre presentes
- `active_scan`: Se active_scan=True
- `has_critical_findings`: Se encontrou vulnerabilidades críticas

### 2. Spans de Tool Execution

```python
# Em LangGraphAgent._run_node()
result, duration_ms, error = observability.track_tool_execution(
    tool_name="nuclei_scan",
    domain="example.com",
    execution_fn=lambda: tool_fn(domain),
)
```

**Scores automáticos**:
- `success`: 1.0 (sucesso) ou 0.0 (erro)
- `latency`: 1.0 (<1s), 0.5 (<5s), 0.2 (≥5s)

**Metadados**:
- `status`: "success" | "error"
- `duration_ms`: Tempo de execução
- `has_error`: bool

### 3. LLM Call Tracking

Rastreia **todas** as chamadas de LLM com token usage e custos:

#### 3.1 Incremental Analysis

```python
# Em LLMReporter.analyze_incremental()
observability.track_llm_call(
    component="incremental_analysis.nuclei",
    model="gpt-4o-mini",
    prompt=prompt,
    response=response,
    metadata={
        "tool": "nuclei",
        "domain": "example.com",
        "output_length": 45231,
        "truncated": True,
    },
)
```

#### 3.2 Final Report

```python
# Em LLMReporter.generate()
observability.track_llm_call(
    component="final_report",
    model="gpt-4o-mini",
    prompt=prompt,
    response=response,
    metadata={
        "findings_count": 14,
        "tools_executed": 8,
    },
)
```

#### 3.3 Planner

```python
# Em LLMPlanner.plan()
observability.track_llm_call(
    component="planner",
    model="gpt-4o-mini",
    prompt=prompt,
    response=resp,
    metadata={
        "available_tools": 25,
        "completed_tools": 3,
    },
)
```

**Scores automáticos**:
- `cost_efficiency`: 1.0 (<$0.01), 0.5 (<$0.05), 0.2 (≥$0.05)
- `token_efficiency`: output_tokens / input_tokens (ratio)

**Metadados**:
- `component`: Origem da chamada
- `model`: Nome do modelo
- `input_tokens`: Tokens de entrada
- `output_tokens`: Tokens de saída
- `total_tokens`: Soma
- `cost_usd`: Custo calculado

### 4. Embedding Tracking

Rastreia todas as gerações de embeddings:

```python
# Em VectorPlaybookStore
observability.track_embedding(
    text="Django ORM detected in dependencies",
    model="text-embedding-3-small",
    cached=False,  # Redis cache miss
    metadata={"context": "playbook_query"},
)
```

**Scores automáticos**:
- `cache_hit`: 1.0 (cached) ou 0.0 (API call)

**Metadados**:
- `model`: Nome do modelo de embedding
- `cached`: bool
- `estimated_tokens`: len(text) // 4
- `text_length`: Tamanho do texto
- `context`: "playbook_load" | "playbook_query"

### 5. Trace Scores

Scores agregados adicionados ao final do trace:

```python
# Em LangGraphAgent.run()
observability.add_trace_score(
    name="findings_count",
    value=14,
    comment="14 total findings",
)

observability.add_trace_score(
    name="critical_findings",
    value=3,
    comment="3 critical/high findings",
)

observability.add_trace_score(
    name="scan_coverage",
    value=0.92,
    comment="8 tools executed",
)
```

**Scores disponíveis**:
- `findings_count`: Número total de descobertas
- `critical_findings`: Descobertas críticas/high
- `scan_coverage`: % de ferramentas executadas com sucesso
- `overall_quality`: Score agregado (se implementado)

### 6. Dynamic Tags

Tags adicionadas dinamicamente baseadas no resultado:

```python
tags = ["security", "recon"]
if active_scan:
    tags.append("active_scan")
if critical_findings > 0:
    tags.append("has_critical_findings")

observability.add_trace_tags(tags)
```

Útil para filtrar no dashboard:
- Scans com vulnerabilidades: `has_critical_findings`
- Scans ativos: `active_scan`
- Por tipo: `security`, `recon`

---

## 💰 Cost Tracking

### Modelos Suportados

```python
# Custos por 1M de tokens (USD)
{
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "text-embedding-3-small": {"input": 0.02, "output": 0.00},
}
```

### Cálculo Automático

```python
total_cost = (input_tokens / 1_000_000) * input_price + \
             (output_tokens / 1_000_000) * output_price
```

Custos são adicionados como metadata em cada span de LLM call.

### Visualizar Custos

No dashboard Langfuse:
1. **Analytics** → **Usage**
2. Filtrar por `model`, `component`, `environment`
3. Ver custos agregados por dia/semana/mês
4. Exportar CSV para análise detalhada

---

## 🔍 Queries Úteis no Dashboard

### 1. Scans com Alta Latência

```
Filter:
- Type: Trace
- Tags: security
- Scores: latency < 0.5
```

### 2. Custos por Componente

```
Analytics → Usage
- Group by: metadata.component
- Time: Last 7 days
```

### 3. Cache Efficiency

```
Filter:
- Type: Observation
- Name: embedding_call
- Scores: cache_hit = 1.0
```

Calcular taxa:
```
Cache Hit Rate = (cache_hits / total_embeddings) * 100
```

### 4. Scans com Vulnerabilidades Críticas

```
Filter:
- Type: Trace
- Tags: has_critical_findings
- Scores: critical_findings > 0
```

### 5. Erros de Tools

```
Filter:
- Type: Observation
- Name: tool_execution
- Scores: success = 0.0
```

---

## 📊 Dashboards Recomendados

### Dashboard 1: Overview de Scans

```
KPIs:
- Total Scans (Last 7d)
- Average Cost per Scan
- Success Rate (%)
- Critical Findings Count

Charts:
- Scans over time (line)
- Cost by component (pie)
- Findings by severity (bar)
- Cache hit rate (gauge)
```

### Dashboard 2: Performance

```
KPIs:
- P50/P95 Latency
- Average Tools per Scan
- Failure Rate (%)
- Token Efficiency

Charts:
- Latency distribution (histogram)
- Tool execution times (bar)
- Token usage by model (stacked area)
```

### Dashboard 3: Costs

```
KPIs:
- Total Cost (MTD)
- Cost per Finding
- Most Expensive Component
- Cache Savings

Charts:
- Daily cost trend (line)
- Cost by environment (pie)
- Token usage breakdown (stacked bar)
- Cache hit rate trend (line)
```

---

## 🎯 Best Practices

### 1. Session Management

Agrupe scans relacionados usando `session_id`:

```python
# Antes de múltiplos scans
obs = get_observability()
obs.set_session("project_alpha_recon")

# Todos os scans seguintes serão agrupados
agent.run("example.com")
agent.run("api.example.com")
agent.run("test.example.com")
```

### 2. Custom Metadata

Adicione contexto extra quando necessário:

```python
with observability.trace_scan(
    domain=domain,
    active_scan=active_scan,
    metadata={
        "client": "Acme Corp",
        "project": "Q1 2026 Pentest",
        "tester": "security@example.com",
        "scope": ["web", "api", "mobile"],
    },
):
    # Execute scan
    pass
```

### 3. Score Customizado

Adicione scores específicos do seu negócio:

```python
# Exemplo: compliance score
compliance_passed = check_compliance(findings)
observability.add_trace_score(
    name="compliance_score",
    value=1.0 if compliance_passed else 0.0,
    comment="OWASP Top 10 compliance",
)
```

### 4. Alertas

Configure alertas no Langfuse para:
- **Custo alto**: trace score `cost > $1.00`
- **Muitos erros**: count(success = 0.0) > 3
- **Baixa eficiência**: cache_hit_rate < 0.7
- **Vulnerabilidades críticas**: critical_findings > 0

### 5. Performance Monitoring

Compare performance ao longo do tempo:

```python
# Antes
Average scan duration: 45s
Average cost: $0.35
Cache hit rate: 45%

# Depois de otimizações
Average scan duration: 28s (-38%)
Average cost: $0.21 (-40%)
Cache hit rate: 82% (+37pp)
```

---

## 🔧 Troubleshooting

### Observability não aparece no dashboard

```bash
# 1. Verificar variáveis de ambiente
env | grep LANGFUSE

# 2. Testar conexão
python -c "from fackel.core.observability import get_observability; obs = get_observability(); print(f'Enabled: {obs.enabled}')"

# 3. Verificar logs
tail -f fackel.log | grep observability
```

### Custos não aparecem

```python
# Verificar se response tem metadata
response = llm.invoke(prompt)
print(response.response_metadata)
# Deve conter: {'token_usage': {'prompt_tokens': X, 'completion_tokens': Y}}
```

### Cache não está funcionando

```bash
# Verificar Redis
redis-cli -h localhost -p 6379 -n 1 PING
# Deve retornar: PONG

# Ver cache hits
redis-cli -h localhost -p 6379 -n 1 INFO stats | grep hits
```

### Spans órfãos (sem parent trace)

```python
# Sempre use o context manager
with observability.trace_scan(...):
    # Operações aqui terão parent trace correto
    pass

# ❌ Evitar chamar fora do contexto
observability.track_llm_call(...)  # Sem parent!
```

---

## 🚀 Próximos Passos

### P1 - Melhorias Planejadas

1. **Feedback Loop**
   - Adicionar UI para marcar findings como false positive
   - Enviar feedback scores para Langfuse
   - Usar feedback para fine-tuning

2. **Anomaly Detection**
   - Alertas automáticos para scans anormais
   - Baseline de custos por domínio
   - Detecção de regressão de qualidade

3. **Multi-Model Support**
   - Comparar GPT-4o-mini vs GPT-3.5
   - A/B testing automático
   - Cost/quality tradeoff analysis

4. **Advanced Analytics**
   - Custom dashboards por projeto
   - ROI calculation (custo vs findings)
   - Trend analysis de vulnerabilidades

### P2 - Recursos Avançados

1. **Dataset Export**
   - Exportar traces para fine-tuning
   - Criar golden examples automaticamente
   - Version control de prompts

2. **Integration com SIEM**
   - Push findings para Splunk/Elastic
   - Correlation com security events
   - Automated incident creation

3. **Compliance Reporting**
   - OWASP Top 10 coverage
   - CIS Benchmarks checklist
   - Automated compliance reports

---

## 📚 Recursos

### Documentação Oficial

- [Langfuse Docs](https://langfuse.com/docs)
- [Langfuse Cookbook](https://langfuse.com/docs/integrations)
- [Python SDK](https://langfuse.com/docs/sdk/python)
- [LangChain Integration](https://langfuse.com/docs/integrations/langchain)

### Implementação Fackel

- [observability.py](../src/fackel/core/observability.py) - Core module
- [graph_agent.py](../src/fackel/agents/graph_agent.py) - Trace management
- [reporter.py](../src/fackel/agents/reporter.py) - LLM tracking
- [vector_store.py](../src/fackel/agents/vector_store.py) - Embedding tracking

### Exemplos

```bash
# Ver exemplo de scan com observability
uv run fackel run example.com

# Executar com debug
LANGFUSE_DEBUG=true uv run fackel run example.com
```

---

## ✅ Checklist de Verificação

Use este checklist para garantir observability completa:

```
Configuração:
[ ] LANGFUSE_PUBLIC_KEY configurado
[ ] LANGFUSE_SECRET_KEY configurado
[ ] LANGFUSE_HOST acessível
[ ] Conexão testada com get_observability()

Traces:
[ ] Trace criado para cada scan
[ ] Metadata completo (domain, active_scan, etc.)
[ ] Tags apropriadas adicionadas
[ ] Session ID configurado (se múltiplos scans)

Spans:
[ ] Tool executions rastreados
[ ] LLM calls rastreados (planner, analyzer, reporter)
[ ] Embeddings rastreados
[ ] Durations corretas

Scores:
[ ] Success/failure por tool
[ ] Latency scores (<1s, <5s, ≥5s)
[ ] Cost efficiency (<$0.01, <$0.05, ≥$0.05)
[ ] Cache hit rate (embeddings)
[ ] Trace scores (findings, coverage)

Custos:
[ ] Token usage capturado (input + output)
[ ] Custos calculados corretamente
[ ] Breakdown por component visível no dashboard

Dashboard:
[ ] Traces aparecem em real-time
[ ] Scores visíveis e corretos
[ ] Analytics mostra custos
[ ] Filtros funcionam (tags, scores, dates)
```

---

**Observability Status**: 🟢 Totalmente implementado com todos os recursos principais do Langfuse!
