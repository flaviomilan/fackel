# LLM Best Practices - Roadmap de Melhorias

## 🎯 Status Atual

### ✅ Já Implementado
- Streaming API (SSE)
- Observabilidade com Langfuse
- Redis cache para embeddings
- Incremental analysis (análise por tool)
- Adaptive policy engine com vector store
- Configuração centralizada

### 🚧 Próximas Melhorias Prioritárias

---

## 1. 🧪 Evaluation & Quality Assurance

### 1.1 LLM-as-Judge para Avaliação Automática
```python
# src/fackel/evaluation/judges.py
class LLMJudge:
    """Avalia qualidade das respostas do LLM."""
    
    def evaluate_incremental_analysis(self, tool_output: str, analysis: str) -> dict:
        """
        Critérios:
        - Relevância: análise focada em findings de segurança
        - Completude: capturou todas vulnerabilidades mencionadas
        - Precisão: sem alucinações ou false positives
        - Acionabilidade: informações úteis para exploração
        """
        prompt = f"""
        Você é um avaliador de qualidade para análises de segurança.
        
        OUTPUT DA FERRAMENTA:
        {tool_output[:2000]}
        
        ANÁLISE GERADA:
        {analysis}
        
        Avalie a análise de 0-10 em:
        1. Relevância (só info de segurança)
        2. Completude (capturou tudo importante)
        3. Precisão (sem alucinações)
        4. Acionabilidade (útil para exploração)
        
        Retorne JSON:
        {{"scores": {{"relevance": 0-10, ...}}, "feedback": "...", "overall": 0-10}}
        """
        # Implementar com GPT-4o-mini ou outro modelo
```

**Benefícios:**
- Detecta degradação de qualidade
- Identifica prompts que precisam ajuste
- Baseline para comparar modelos

### 1.2 Dataset de Golden Examples
```yaml
# tests/fixtures/golden_examples.yaml
- tool: nuclei_scan
  output: "[critical] SQL Injection in /api/login"
  expected_analysis:
    - mentions: ["SQL Injection", "critical", "/api/login"]
    - severity: "critical"
    - contains_evidence: true
  
- tool: whois_lookup
  output: "Domain: example.com\nRegistrar: GoDaddy"
  expected_analysis:
    - should_return_empty: true  # Não é security finding
```

**Implementação:**
```bash
# CI/CD validation
pytest tests/test_llm_quality.py --golden-set
```

### 1.3 Regression Testing
```python
# tests/test_llm_regression.py
def test_analysis_quality_regression():
    """Garante que mudanças não degradam qualidade."""
    for example in load_golden_examples():
        analysis = reporter.analyze_incremental(example.tool, example.output)
        score = judge.evaluate(example.output, analysis)
        assert score["overall"] >= QUALITY_THRESHOLD
```

---

## 2. 💰 Cost Optimization

### 2.1 Token Usage Tracking
```python
# src/fackel/core/token_tracker.py
class TokenTracker:
    def __init__(self):
        self.usage = defaultdict(lambda: {"input": 0, "output": 0, "cost": 0})
    
    def track_call(self, model: str, usage: dict):
        """Track tokens: {prompt_tokens: X, completion_tokens: Y}"""
        self.usage[model]["input"] += usage["prompt_tokens"]
        self.usage[model]["output"] += usage["completion_tokens"]
        self.usage[model]["cost"] += self._calculate_cost(model, usage)
    
    def report(self) -> dict:
        return {
            "total_cost": sum(v["cost"] for v in self.usage.values()),
            "by_model": dict(self.usage),
            "by_component": {
                "planner": self.usage["planner"],
                "reporter": self.usage["reporter"],
                "embeddings": self.usage["embeddings"]
            }
        }
```

**Dashboard:**
```python
# Adicionar ao final do relatório
print(f"\n💰 Token Usage:")
print(f"   Total cost: ${tracker.total_cost:.4f}")
print(f"   Planner: {tracker.usage['planner']['input']} tokens")
print(f"   Analysis: {tracker.usage['reporter']['output']} tokens")
```

### 2.2 Smart Truncation Strategy
```python
# Ao invés de truncar cegamente em 32k:
def smart_truncate(tool_output: str, tool_name: str, max_tokens: int = 8000):
    """Trunca mantendo contexto relevante."""
    
    if tool_name == "nuclei_scan":
        # Prioriza findings críticos
        return extract_by_severity(tool_output, ["critical", "high"], max_tokens)
    
    elif tool_name == "nmap_port_scan":
        # Agrupa portas similares
        return summarize_port_ranges(tool_output, max_tokens)
    
    elif tool_name == "httpx_scan":
        # Prioriza status codes não-200
        return filter_interesting_responses(tool_output, max_tokens)
    
    # Default: primeiros + últimos tokens
    return tool_output[:max_tokens//2] + "\n...\n" + tool_output[-max_tokens//2:]
```

### 2.3 Batch Processing
```python
# Ao invés de analisar cada tool individualmente:
async def analyze_batch(tools_outputs: list[tuple[str, str]]) -> list[str]:
    """Analisa múltiplas ferramentas em uma única chamada."""
    
    prompt = "Analise as seguintes saídas de ferramentas:\n\n"
    for tool, output in tools_outputs[:5]:  # Max 5 por batch
        prompt += f"## {tool}\n{output[:2000]}\n\n"
    
    prompt += "Para cada ferramenta, retorne findings em JSON..."
    
    # 1 chamada ao invés de N chamadas
    return await llm.ainvoke(prompt)
```

---

## 3. 🔒 Security & Safety

### 3.1 Prompt Injection Defense
```python
# src/fackel/core/safety.py
class PromptGuard:
    INJECTION_PATTERNS = [
        r"ignore previous instructions",
        r"disregard.*context",
        r"you are now.*role",
        r"forget.*system message"
    ]
    
    def sanitize_input(self, user_input: str) -> str:
        """Remove tentativas de prompt injection."""
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                raise SecurityError("Potential prompt injection detected")
        
        return user_input
    
    def validate_tool_output(self, output: str) -> str:
        """Garante que output de ferramenta não contém injection."""
        # Escape markdown/código que poderia manipular o LLM
        return escape_special_tokens(output)
```

### 3.2 Content Moderation
```python
# Integrar OpenAI Moderation API
async def check_safety(text: str) -> bool:
    """Detecta conteúdo proibido antes de enviar ao LLM."""
    response = await openai.moderations.create(input=text)
    return not response.results[0].flagged
```

### 3.3 PII Redaction
```python
# src/fackel/core/pii_filter.py
def redact_pii(text: str) -> str:
    """Remove dados sensíveis antes de análise."""
    # Emails
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                  '[EMAIL_REDACTED]', text)
    # Credit cards
    text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 
                  '[CARD_REDACTED]', text)
    # API keys (patterns genéricos)
    text = re.sub(r'\b[A-Za-z0-9]{32,}\b', '[KEY_REDACTED]', text)
    
    return text
```

---

## 4. 📊 Advanced Observability

### 4.1 Spans Customizados no Langfuse
```python
# src/fackel/core/telemetry.py (melhorar)
from langfuse.decorators import observe, langfuse_context

@observe(name="incremental_analysis")
def analyze_incremental(tool_name: str, tool_output: str, domain: str):
    # Adicionar metadados customizados
    langfuse_context.update_current_trace(
        tags=["security", "pentest", tool_name],
        metadata={
            "domain": domain,
            "output_length": len(tool_output),
            "tool": tool_name
        }
    )
    
    # Adicionar input/output para debugging
    langfuse_context.update_current_observation(
        input={"tool": tool_name, "output_preview": tool_output[:500]},
        output=analysis
    )
    
    return analysis
```

### 4.2 Scores Automáticos
```python
# Enviar scores para Langfuse
langfuse_context.score_current_observation(
    name="quality",
    value=evaluation_score,
    comment="LLM-as-judge evaluation"
)

langfuse_context.score_current_trace(
    name="cost",
    value=total_tokens * COST_PER_TOKEN,
    data_type="numeric"
)
```

### 4.3 Alertas de Anomalias
```python
# src/fackel/monitoring/alerts.py
class AnomalyDetector:
    def check_latency_spike(self, duration_ms: float):
        if duration_ms > THRESHOLD_P95 * 2:
            send_alert(f"LLM latency spike: {duration_ms}ms")
    
    def check_cost_spike(self, cost: float):
        if cost > DAILY_BUDGET * 0.1:  # 10% do budget em um scan
            send_alert(f"Cost anomaly: ${cost}")
    
    def check_quality_drop(self, score: float):
        if score < QUALITY_BASELINE - 2:  # 2 desvios padrão
            send_alert(f"Quality degradation: {score}")
```

---

## 5. 🧠 Advanced Prompting Techniques

### 5.1 Few-Shot Examples (In-Context Learning)
```python
# src/fackel/prompts/incremental_analysis.py
EXAMPLES = """
# Exemplo 1: Nuclei Scan
Input: [high] CORS Misconfiguration at https://api.example.com
Output:
- **[HIGH]** CORS Misconfiguration
  - Endpoint: https://api.example.com
  - Impacto: Permite requisições cross-origin de qualquer domínio
  - Exploitabilidade: Alta
  - Evidência: `Access-Control-Allow-Origin: *`

# Exemplo 2: Whois
Input: Domain: example.com, Registrar: GoDaddy, Created: 2010-01-01
Output: No significant findings.
"""

def build_prompt_with_examples(tool_name: str, tool_output: str):
    return f"{SYSTEM_PROMPT}\n\n{EXAMPLES}\n\n# Análise:\nInput: {tool_output}\nOutput:"
```

### 5.2 Chain-of-Thought (Raciocínio Explícito)
```python
prompt = """
Analise a saída da ferramenta seguindo este raciocínio:

1. **Identificar** todas as vulnerabilidades/exposições mencionadas
2. **Classificar** por severidade (Critical/High/Medium/Low)
3. **Validar** se são findings reais ou false positives
4. **Extrair** evidências exatas (URLs, headers, CVEs)
5. **Resumir** em formato técnico e acionável

Pense passo a passo:
[raciocínio aqui]

Análise final:
[output aqui]
"""
```

### 5.3 Self-Consistency (Múltiplas Gerações)
```python
async def analyze_with_consensus(tool_output: str, n_samples: int = 3):
    """Gera N análises e seleciona a mais consistente."""
    
    analyses = await asyncio.gather(*[
        llm.ainvoke(prompt, temperature=0.7) for _ in range(n_samples)
    ])
    
    # Extrai findings de cada análise
    all_findings = [extract_findings(a) for a in analyses]
    
    # Retorna apenas findings presentes em 2+ análises
    consensus_findings = find_consensus(all_findings, threshold=2)
    
    return format_findings(consensus_findings)
```

---

## 6. 🔄 Continuous Learning

### 6.1 Feedback Loop
```python
# src/fackel/feedback/collector.py
class FeedbackCollector:
    def collect(self, analysis_id: str, feedback: dict):
        """
        feedback = {
            "rating": 1-5,
            "issues": ["missed_vuln", "false_positive", ...],
            "comment": "...",
            "corrected_analysis": "..."
        }
        """
        # Salvar no Langfuse como annotation
        langfuse.score(
            trace_id=analysis_id,
            name="user_feedback",
            value=feedback["rating"],
            comment=feedback["comment"]
        )
        
        # Adicionar ao dataset de fine-tuning
        if feedback.get("corrected_analysis"):
            save_to_finetune_dataset(feedback)
```

### 6.2 Fine-Tuning Dataset Builder
```bash
# Exportar dados do Langfuse para fine-tuning
python scripts/export_training_data.py \
  --min-score 4 \
  --annotations user_feedback \
  --output training_data.jsonl
```

```jsonl
{"messages": [
  {"role": "system", "content": "..."},
  {"role": "user", "content": "Analise: [nuclei output]"},
  {"role": "assistant", "content": "[análise corrigida pelo usuário]"}
]}
```

### 6.3 Model Versioning
```python
# src/fackel/config/models.py
MODEL_REGISTRY = {
    "planner": {
        "production": "gpt-4o-mini",
        "canary": "ft:gpt-4o-mini-2024:fackel:v1",
        "rollout": 0.1  # 10% do tráfego usa canary
    },
    "reporter": {
        "production": "gpt-4o-mini",
        "champion": "gpt-4o-mini",
        "challenger": "gpt-3.5-turbo-16k",  # A/B test
        "rollout": 0.5
    }
}
```

---

## 7. 🏗️ Architecture Patterns

### 7.1 Tool-Specific Analyzers
```python
# src/fackel/agents/analyzers/nuclei_analyzer.py
class NucleiAnalyzer:
    """Especializado em analisar outputs do Nuclei."""
    
    SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    
    def analyze(self, output: dict) -> dict:
        findings = self.parse_nuclei_json(output)
        
        # Lógica específica do Nuclei
        deduplicated = self.deduplicate_templates(findings)
        prioritized = self.prioritize_by_exploitability(deduplicated)
        
        return {
            "critical_count": len([f for f in prioritized if f.severity == "critical"]),
            "findings": prioritized,
            "risk_score": self.calculate_risk(prioritized)
        }
```

### 7.2 Agent Orchestration (Multi-Agent)
```python
# src/fackel/agents/orchestrator.py
class AgentOrchestrator:
    """Coordena múltiplos agentes especializados."""
    
    def __init__(self):
        self.recon_agent = ReconAgent()  # Foca em descoberta
        self.vuln_agent = VulnAgent()    # Foca em vulnerabilidades
        self.exploit_agent = ExploitAgent()  # Foca em exploração
    
    async def run_pipeline(self, domain: str):
        # 1. Recon
        assets = await self.recon_agent.discover(domain)
        
        # 2. Vuln scanning (em paralelo para cada asset)
        vulns = await asyncio.gather(*[
            self.vuln_agent.scan(asset) for asset in assets
        ])
        
        # 3. Exploit validation (apenas vulns HIGH+)
        critical_vulns = [v for v in vulns if v.severity >= "high"]
        exploits = await self.exploit_agent.validate(critical_vulns)
        
        return self.generate_report(exploits)
```

### 7.3 Memory & Context Management
```python
# src/fackel/core/memory.py
class AgentMemory:
    """Mantém contexto entre execuções de ferramentas."""
    
    def __init__(self, max_tokens: int = 16000):
        self.max_tokens = max_tokens
        self.observations = []
        self.hypotheses = []
    
    def add_observation(self, tool: str, finding: str):
        """Adiciona nova observação ao contexto."""
        self.observations.append({"tool": tool, "finding": finding})
        self._trim_if_needed()
    
    def add_hypothesis(self, hypothesis: str, confidence: float):
        """LLM pode criar hipóteses sobre o alvo."""
        self.hypotheses.append({"text": hypothesis, "confidence": confidence})
    
    def get_context(self) -> str:
        """Contexto comprimido para próxima chamada LLM."""
        return f"""
        Observações anteriores:
        {format_observations(self.observations[-5:])}
        
        Hipóteses em teste:
        {format_hypotheses(self.hypotheses)}
        """
```

---

## 8. 🎨 User Experience

### 8.1 Interactive Mode
```bash
# fackel interactive example.com
> [Agent] Found WordPress site. Recommend nuclei CMS scan?
> User: yes
> [Agent] Running nuclei_scan...
> [Agent] Found 3 HIGH vulns. Exploit validation? [y/n]
> User: y
> [Agent] Validated 1/3 exploits. Generate PoC? [y/n]
```

### 8.2 Explain Mode
```python
# adicionar flag --explain
def analyze_with_explanation(tool_output: str):
    analysis = llm.invoke(prompt)
    
    explanation = llm.invoke(f"""
    Você gerou esta análise: {analysis}
    
    Explique:
    1. Por que classificou cada finding com essa severidade
    2. Quais padrões você identificou no output
    3. Quais findings você descartou e por quê
    """)
    
    return {
        "analysis": analysis,
        "explanation": explanation  # Mostrar com --explain
    }
```

### 8.3 Confidence Scores
```python
# Adicionar confiança a cada finding
{
    "finding": "SQL Injection at /api/login",
    "severity": "critical",
    "confidence": 0.95,  # 95% confiante
    "reasoning": "Pattern matched: sleep-based detection + error message"
}
```

---

## 9. 📦 Production Readiness

### 9.1 Rate Limiting & Retry Logic
```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    reraise=True
)
async def llm_call_with_retry(prompt: str):
    try:
        return await llm.ainvoke(prompt)
    except RateLimitError as e:
        logger.warning(f"Rate limited: {e}")
        raise  # Trigger retry
```

### 9.2 Fallback Models
```python
async def call_with_fallback(prompt: str):
    """Tenta modelo primário, cai para backup se falhar."""
    try:
        return await llm_primary.ainvoke(prompt, timeout=30)
    except (TimeoutError, APIError):
        logger.warning("Primary model failed, using fallback")
        return await llm_fallback.ainvoke(prompt, timeout=60)
```

### 9.3 Circuit Breaker
```python
from pybreaker import CircuitBreaker

llm_breaker = CircuitBreaker(
    fail_max=5,
    timeout_duration=60
)

@llm_breaker
async def protected_llm_call(prompt: str):
    """Para de chamar LLM se muitas falhas consecutivas."""
    return await llm.ainvoke(prompt)
```

---

## 10. 🔬 Experimental Features

### 10.1 Retrieval-Augmented Generation (RAG)
```python
# src/fackel/rag/knowledge_base.py
class SecurityKnowledgeBase:
    """RAG para enriquecer análises com conhecimento externo."""
    
    def __init__(self):
        self.vector_store = ChromaDB()
        self.load_knowledge_base([
            "docs/exploit_techniques.md",
            "docs/cve_database.json",
            "docs/security_best_practices.md"
        ])
    
    async def enrich_analysis(self, finding: str) -> str:
        # Busca contexto relevante
        relevant_docs = self.vector_store.similarity_search(finding, k=3)
        
        prompt = f"""
        Finding: {finding}
        
        Conhecimento relevante:
        {format_docs(relevant_docs)}
        
        Enriqueça a análise com:
        - Contexto técnico adicional
        - Referências a CVEs similares
        - Técnicas de exploração conhecidas
        """
        
        return await llm.ainvoke(prompt)
```

### 10.2 Multi-Modal Analysis
```python
# Analisar screenshots de ferramentas visuais
async def analyze_screenshot(image_path: str, tool: str):
    """GPT-4V para analisar screenshots (ex: Burp, ZAP)."""
    
    with open(image_path, "rb") as f:
        base64_image = base64.b64encode(f.read()).decode()
    
    response = await openai.chat.completions.create(
        model="gpt-4-vision-preview",
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": "Analise este screenshot do Burp Suite:"},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}}
            ]
        }]
    )
    
    return response.choices[0].message.content
```

### 10.3 Code Generation (Exploit PoCs)
```python
async def generate_exploit_poc(vuln: dict) -> str:
    """Gera PoC Python para vulnerabilidade."""
    
    prompt = f"""
    Você é um pentester expert. Gere um exploit PoC em Python para:
    
    Vulnerabilidade: {vuln['type']}
    Target: {vuln['url']}
    Parâmetro: {vuln['parameter']}
    Payload: {vuln['payload']}
    
    Requisitos:
    - Código funcional e testável
    - Comentários explicativos
    - Tratamento de erros
    - Safe mode (apenas detectar, não explorar)
    """
    
    code = await llm.ainvoke(prompt)
    
    # Validar código gerado
    if not is_safe_code(code):
        raise SecurityError("Generated code contains unsafe patterns")
    
    return code
```

---

## 📋 Implementation Priority

### P0 (Crítico - Próximo Sprint)
1. Token tracking & cost monitoring
2. LLM-as-judge para regression tests
3. Prompt injection defense
4. Smart truncation strategy

### P1 (Alta - Próximo Mês)
5. Golden examples dataset
6. Enhanced Langfuse spans
7. Few-shot examples in prompts
8. Tool-specific analyzers

### P2 (Média - Próximo Trimestre)
9. Feedback loop system
10. Multi-agent orchestration
11. Advanced memory management
12. RAG knowledge base

### P3 (Baixa - Backlog)
13. Multi-modal analysis
14. Fine-tuning pipeline
15. Code generation
16. Interactive mode

---

## 📚 Referências

- [OpenAI Best Practices](https://platform.openai.com/docs/guides/prompt-engineering)
- [LangChain Production Patterns](https://python.langchain.com/docs/guides/productionization/)
- [Langfuse Cookbook](https://langfuse.com/docs/integrations)
- [Anthropic Prompt Engineering Guide](https://docs.anthropic.com/claude/docs/prompt-engineering)
- [Google Gemini Best Practices](https://ai.google.dev/gemini-api/docs/prompting-strategies)
