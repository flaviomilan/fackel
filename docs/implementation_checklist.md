# Quick Implementation Checklist

Use este checklist para implementar as melhorias prioritárias de forma incremental.

---

## ✅ P0 - Implementar Esta Semana (4-6 horas)

### [ ] 1. Token Tracking (30 min)

**Passo 1:** Importar tracker no graph_agent.py
```python
# No topo de graph_agent.py
from fackel.core.token_tracker import get_tracker
```

**Passo 2:** Adicionar tracking no método run()
```python
# No final de LangGraphAgent.run(), antes do return:
tracker = get_tracker()
tracker.print_summary()
```

**Passo 3:** Integrar no reporter.py
```python
# Em analyze_incremental(), após llm.invoke():
tracker = get_tracker()
if hasattr(response, 'response_metadata'):
    usage = response.response_metadata.get('token_usage', {})
    tracker.track(
        component=f"incremental_analysis.{tool_name}",
        model="gpt-4o-mini",
        input_tokens=usage.get('prompt_tokens', 0),
        output_tokens=usage.get('completion_tokens', 0)
    )
```

**Teste:**
```bash
uv run fackel run example.com
# Deve mostrar sumário de tokens no final
```

---

### [ ] 2. Smart Truncation (45 min)

**Passo 1:** Importar no reporter.py
```python
from fackel.core.smart_truncate import smart_truncate
```

**Passo 2:** Substituir truncação simples
```python
# ANTES:
truncated_output = tool_output[:32000]
if len(tool_output) > 32000:
    truncated_output += "\n...(output truncated)..."

# DEPOIS:
truncated_output = smart_truncate(tool_output, tool_name, max_chars=32000)
```

**Teste:**
```bash
# Testar com Nuclei (grandes outputs)
uv run fackel run example.com --active-scan
# Verificar que findings HIGH/CRITICAL são preservados
```

---

### [ ] 3. Tracking em Embeddings (30 min)

**Passo 1:** Modificar vector_store.py
```python
from fackel.core.token_tracker import get_tracker
from fackel.core.smart_truncate import estimate_tokens

# Em _vector_match(), após embed_query():
tracker = get_tracker()
if query_emb is None:
    query_emb = np.array(self._embedder.embed_query(query))
    
    # Track embedding call
    tracker.track(
        component="embeddings.query",
        model="text-embedding-3-small",
        input_tokens=estimate_tokens(query),
        output_tokens=0
    )
```

**Passo 2:** Tracking em playbook embeddings
```python
# Em _load_playbooks(), ao gerar embeddings:
if cached is None:
    embedding = self._embedder.embed_query(text)
    
    tracker.track(
        component="embeddings.playbook",
        model="text-embedding-3-small",
        input_tokens=estimate_tokens(text),
        output_tokens=0
    )
```

---

### [ ] 4. Cost Alerts (15 min)

**Passo 1:** Adicionar warning em graph_agent.py
```python
# No final de run(), após tracker.print_summary():
report = tracker.report()
if report['total_cost_usd'] > 0.50:
    self.logger.warning(
        f"⚠️  High cost scan: ${report['total_cost_usd']:.2f}. "
        "Consider enabling Redis cache and optimizing truncation."
    )
```

---

## ✅ P1 - Próximos 30 Dias (2-3 dias)

### [ ] 5. Golden Examples Dataset (3-4 horas)

**Passo 1:** Criar fixtures
```bash
mkdir -p tests/fixtures/golden_examples/
```

**Passo 2:** Criar YAML com exemplos
```yaml
# tests/fixtures/golden_examples/nuclei.yaml
- tool: nuclei_scan
  input: |
    [critical] SQL Injection found at /api/login
    [high] XSS vulnerability at /search?q=
  expected:
    - severity: critical
      vuln_type: SQL Injection
      endpoint: /api/login
    - severity: high
      vuln_type: XSS
      endpoint: /search
```

**Passo 3:** Criar test
```python
# tests/test_llm_quality.py
import pytest
import yaml

def test_golden_examples():
    examples = yaml.safe_load(open("tests/fixtures/golden_examples/nuclei.yaml"))
    
    for example in examples:
        analysis = reporter.analyze_incremental(
            example['tool'],
            example['input'],
            "example.com"
        )
        
        # Verificar que análise menciona vulnerabilidades esperadas
        for expected in example['expected']:
            assert expected['vuln_type'] in analysis
            assert expected['endpoint'] in analysis
```

---

### [ ] 6. Few-Shot Examples (2-3 horas)

**Passo 1:** Criar módulo de prompts
```python
# src/fackel/prompts/__init__.py
INCREMENTAL_EXAMPLES = """
# Exemplo 1: Nuclei (Critical Finding)
Tool: nuclei_scan
Output: [critical] SQL Injection at https://api.example.com/login
Analysis:
- **[CRITICAL]** SQL Injection
  - Endpoint: https://api.example.com/login
  - Impacto: Database compromise, data exfiltration
  - Evidência: `[critical] SQL Injection`

# Exemplo 2: WHOIS (No Findings)
Tool: whois_lookup
Output: Domain: example.com, Registrar: GoDaddy, Created: 2010
Analysis: No significant findings.
"""
```

**Passo 2:** Integrar no reporter
```python
from fackel.prompts import INCREMENTAL_EXAMPLES

prompt = f"""
{SYSTEM_INSTRUCTIONS}

{INCREMENTAL_EXAMPLES}

# Nova Análise:
Tool: {tool_name}
Output: {truncated_output}
Analysis:
"""
```

---

### [ ] 7. Enhanced Langfuse Spans (2 horas)

**Passo 1:** Adicionar decorators
```python
from langfuse.decorators import observe, langfuse_context

@observe(name="incremental_analysis")
def analyze_incremental(self, tool_name, tool_output, domain):
    # Adicionar metadados
    langfuse_context.update_current_trace(
        tags=["security", tool_name],
        metadata={
            "domain": domain,
            "tool": tool_name,
            "output_length": len(tool_output)
        }
    )
    
    # ... análise ...
    
    # Adicionar score
    langfuse_context.score_current_observation(
        name="token_cost",
        value=estimated_cost,
        data_type="numeric"
    )
    
    return analysis
```

---

### [ ] 8. Prompt Injection Defense (1-2 horas)

**Passo 1:** Criar safety module
```python
# src/fackel/core/safety.py
import re

INJECTION_PATTERNS = [
    r"ignore (previous|all) instructions",
    r"disregard.*context",
    r"you are now",
    r"new role.*:",
    r"system.*override"
]

def check_prompt_injection(text: str) -> bool:
    """Returns True if injection detected."""
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def sanitize_tool_output(output: str) -> str:
    """Remove potential injection attempts from tool output."""
    if check_prompt_injection(output):
        logger.warning("Potential prompt injection in tool output")
        # Escape or truncate suspicious sections
    return output
```

**Passo 2:** Integrar no reporter
```python
from fackel.core.safety import sanitize_tool_output

def analyze_incremental(self, tool_name, tool_output, domain):
    # Sanitize before sending to LLM
    safe_output = sanitize_tool_output(tool_output)
    # ... rest of analysis ...
```

---

## 🧪 Testing Checklist

Após cada implementação, validar:

### Token Tracking
- [ ] Summary aparece no final do scan
- [ ] Valores de custo são razoáveis ($0.01-$1.00 por scan)
- [ ] Breakdown por componente está correto

### Smart Truncation
- [ ] Nuclei preserva findings HIGH/CRITICAL
- [ ] Katana deduplica URLs similares
- [ ] DNS agrupa por tipo de record
- [ ] Outputs mantém <32kb

### Embeddings Tracking
- [ ] Cache hits não contam tokens
- [ ] Cache misses são tracked
- [ ] Custos de embeddings separados de LLM

### Golden Examples
- [ ] Tests passam com examples atuais
- [ ] CI falha se qualidade degradar
- [ ] Fácil adicionar novos examples

---

## 📊 Métricas de Sucesso

### Antes (Baseline)
```bash
# Run scan e anotar:
- Tempo total: _____ segundos
- Custo estimado: $_____ (se disponível)
- Qualidade subjetiva: 1-10 ____
```

### Depois (Com Melhorias)
```bash
# Após P0:
- [ ] Custo visível e < $0.50 por scan
- [ ] Redução de ~40% nos tokens
- [ ] Findings críticos preservados

# Após P1:
- [ ] Regression tests passando
- [ ] Few-shot melhorando qualidade
- [ ] Langfuse traces detalhados
```

---

## 🚨 Troubleshooting

### Token tracking não aparece
```bash
# Verificar import
python -c "from fackel.core.token_tracker import get_tracker; print('OK')"

# Verificar se LLM retorna usage
# Adicionar debug em reporter.py:
print(response.response_metadata)
```

### Smart truncation muito agressivo
```python
# Aumentar max_chars
smart_truncate(output, tool_name, max_chars=50000)  # Default: 32000
```

### Custo muito alto (>$1 por scan)
```bash
# Check:
1. Redis cache habilitado?
2. Smart truncation ativo?
3. Análise incremental pulando outputs vazios?
4. Embeddings sendo cached?
```

---

## 🎓 Learning Resources

- [ ] Ler [OpenAI Best Practices](https://platform.openai.com/docs/guides/prompt-engineering)
- [ ] Revisar [LangChain Production Guide](https://python.langchain.com/docs/guides/productionization/)
- [ ] Explorar [Langfuse Dashboard](http://localhost:3000)
- [ ] Ler [llm_best_practices.md](llm_best_practices.md) completo

---

**Status:** ____ / 8 P0 tasks completed | ____ / 4 P1 tasks completed

**Próximo Passo:** Começar com Token Tracking (30 min) ⏰
