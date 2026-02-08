# Troubleshooting: Empty Partial Reports

## Problema

Os eventos `partial_report` no streaming API estão retornando análises vazias:

```json
{
  "type": "partial_report",
  "step": "run",
  "details": {
    "tool": "censys_lookup",
    "analysis": "",  // ⚠️ Vazio!
    "timestamp": "..."
  }
}
```

## Causas Identificadas

### 1. Heurística de Skip Muito Agressiva

**Problema anterior** (❌):
```python
# Pulava análise se output < 50 chars OU continha palavra "error"
if len(tool_output) < 50 or "error" in tool_output.lower():
    return ""
```

**Correção implementada** (✅):
```python
# Skip apenas outputs verdadeiramente vazios (<10 chars)
if len(tool_output_stripped) < 10:
    return ""

# Skip apenas mensagens de erro explícitas
error_indicators = [
    "error:",
    "failed to",
    "unable to",
    "no results found",
    # ...
]
```

### 2. Análises Vazias Sendo Adicionadas ao Log

**Problema anterior** (❌):
```python
# Sempre adicionava ao log, mesmo se analysis=""
new_logs.append({"tool": tool_name, "analysis": analysis, ...})
```

**Correção implementada** (✅):
```python
# Só adiciona se análise produziu conteúdo
if analysis and analysis.strip():
    new_logs.append({"tool": tool_name, "analysis": analysis, ...})
else:
    logger.debug(f"⊘ Skipped analysis for {tool_name}")
```

### 3. Falta de Logging Detalhado

**Melhorias implementadas**:
- ✅ Log quando pula por output curto
- ✅ Log quando pula por erro
- ✅ Log do tamanho da análise gerada
- ✅ Símbolos visuais: ✓ (sucesso), ⊘ (skip), ✗ (erro)

## Debugging

### 1. Verificar Logs da Aplicação

```bash
# Executar com logging debug
tail -f fackel.log | grep -E "Skipping|analysis"
```

Você verá:
```
[DEBUG] Skipping analysis for censys_lookup: Output too short (8 chars)
[INFO] Analyzing output for whois_lookup (1234 chars)...
[INFO] ✓ Incremental analysis completed for whois_lookup (456 chars)
[DEBUG] ⊘ Skipped analysis for extract_webpage (no significant findings)
```

### 2. Usar Debug Utility

```bash
# Debug streaming events
python debug_streaming.py example.com

# Verá estatísticas:
# ✅ Scan completed!
#    Total events: 45
#    Partial reports: 20
#    Empty analyses: 8
#    Empty rate: 40.0%
```

### 3. Testar Diretamente

```python
from fackel.agents.reporter import LLMReporter

reporter = LLMReporter()

# Teste com output válido
output = "Domain: example.com\nIP: 93.184.216.34\nRegistrar: GoDaddy"
analysis = reporter.analyze_incremental("whois_lookup", output, "example.com")
print(f"Analysis length: {len(analysis)}")
print(analysis)

# Teste com output vazio
output = ""
analysis = reporter.analyze_incremental("tool", output, "example.com")
print(f"Skipped: {analysis == ''}")
```

## Casos Esperados

### ✅ Análises Devem Ser Geradas

- **WHOIS**: registrar, nameservers, creation date
- **DNSDumpster**: subdomains, DNS records
- **Nuclei**: vulnerabilities com HIGH/CRITICAL
- **Nmap**: open ports, services, versions
- **HTTPx**: status codes, headers, technologies

### ⊘ Análises Devem Ser Puladas

- **API errors**: "API key required", "authentication failed"
- **Tool failures**: "failed to execute", "command not found"
- **Empty results**: "", "no results found"
- **Duplicate info**: outputs muito similares já analisados

## Verificação de Qualidade

### Métricas Saudáveis

```
Empty rate: < 30%  ✅ Bom
Empty rate: 30-50% ⚠️  Revisar heurísticas
Empty rate: > 50%  ❌ Problema - investigar
```

### Checklist

```
[ ] LLM está configurado (OPENAI_API_KEY)
[ ] reporter.llm não é None
[ ] Outputs das tools têm conteúdo (>10 chars)
[ ] Não há mensagens de erro explícitas
[ ] Logs mostram "Analyzing output for..."
[ ] Logs NÃO mostram muitos "Skipping analysis"
[ ] Partial reports contêm texto no campo "analysis"
[ ] Analysis log tem entradas não vazias
```

## Monitoramento com Langfuse

As análises incrementais são rastreadas no Langfuse:

```
Trace: fackel_scan (example.com)
├── Span: tool_execution (whois)
├── Span: llm_call (incremental_analysis.whois)  ← Aqui!
│   ├── input_tokens: 523
│   ├── output_tokens: 87
│   └── cost: $0.0012
```

**Red flags no dashboard**:
- Muitos spans `tool_execution` sem spans `llm_call` correspondentes
- Spans `llm_call` com output_tokens=0
- Cost muito baixo (indicando poucos LLM calls)

## Solução Rápida

Se ainda vir muitas análises vazias:

```bash
# 1. Verificar variáveis de ambiente
env | grep -E "OPENAI|LANGFUSE"

# 2. Testar LLM diretamente
python -c "
from fackel.agents.reporter import LLMReporter
r = LLMReporter()
print('LLM available:', r.llm is not None)
"

# 3. Diminuir threshold de skip
# Em reporter.py, linha ~36, mudar:
if len(tool_output_stripped) < 10:  # Era 10, testar com 5
    return ""

# 4. Ver outputs brutos
# Adicione antes do analyze_incremental:
print(f"Tool {tool_name} output:")
print(output_str[:500])  # Primeiros 500 chars
```

## Next Steps

Se problema persistir:

1. Adicionar configuração de threshold no `defaults.yaml`:
```yaml
llm:
  incremental_analysis:
    min_output_length: 10
    skip_error_messages: true
    max_input_chars: 32000
```

2. Implementar análise em batch para economizar custos:
```python
# Acumular outputs e analisar em lote
batch_analysis = reporter.analyze_batch([
    {"tool": "whois", "output": "..."},
    {"tool": "dns", "output": "..."},
])
```

3. Cache de análises similares (evitar re-análise):
```python
# Hash do output para detectar duplicatas
output_hash = hashlib.md5(output.encode()).hexdigest()
if output_hash in analysis_cache:
    return analysis_cache[output_hash]
```
