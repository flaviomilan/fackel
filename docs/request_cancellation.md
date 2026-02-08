# Gerenciamento de Cancelamento de Requisições

## Problema

Quando um cliente (navegador, app, curl) cancela uma requisição HTTP (fecha a conexão), o servidor continua processando a operação. Isso resulta em:

- ⚠️ **Desperdício de recursos**: CPU, memória, API calls
- ⚠️ **Desperdício de dinheiro**: Chamadas OpenAI desnecessárias
- ⚠️ **Sobrecarga**: Processamento inútil que poderia ser usado por outros clientes
- ⚠️ **Logs poluídos**: Erros ao tentar enviar resposta para cliente desconectado

### Exemplo Real

```bash
# Cliente faz request e cancela (Ctrl+C)
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Liste todas as vulnerabilidades"}'
^C

# Sem cancelamento: Servidor continua processando
# - Gera embedding ($0.000001)
# - Busca no MongoDB
# - Chama GPT-4 ($0.0006)
# - Formata resposta
# - Tenta enviar para cliente (falha - já desconectou)

# Com cancelamento: Servidor detecta e para imediatamente
# - Verifica is_disconnected() em pontos estratégicos
# - Para processamento
# - Libera recursos
# - Salva dinheiro
```

---

## Solução Implementada

### 1. Detecção de Desconexão

Usamos `FastAPI Request.is_disconnected()` para verificar se o cliente ainda está conectado.

### 2. Pontos de Verificação Estratégicos

Verificamos cancelamento em momentos críticos:

```python
# ANTES de operações caras
if await request.is_disconnected():
    # Para processamento
    return early_exit_response
```

#### No Query Endpoint (`/query`)

```python
@app.post("/query")
async def query_scans(request: Request, query_request: QueryRequest):
    # ✅ Checkpoint 1: Logo no início
    if await request.is_disconnected():
        logger.info("Client disconnected before query processing")
        raise HTTPException(status_code=499, detail="Client disconnected")
    
    # Opera Embedding (AWS)
    result = await query_service.query(...)
    
    # QueryService verifica em 3 pontos:
    # ✅ Checkpoint 2: Depois de gerar embedding
    # ✅ Checkpoint 3: Antes de chamar LLM (operação mais cara)
```

#### No Stream Endpoint (`/scan/stream`)

```python
@app.get("/scan/stream")
async def stream_scan(request: Request, domain: str):
    async def event_stream():
        for event in agent.stream_run(domain):
            # ✅ Checkpoint: A cada evento enviado
            if await request.is_disconnected():
                logger.info(f"Client disconnected, stopping scan...")
                break
            
            yield event
```

### 3. Benefícios Mensuráveis

| Cenário | Sem Cancelamento | Com Cancelamento | Economia |
|---------|------------------|------------------|----------|
| Query cancelada após 1s | $0.0006 (LLM executado) | $0.000001 (só embedding) | 99.8% |
| Scan cancelado após 10s | 100% CPU por 5min | CPU liberado imediatamente | ~95% |
| 10 requests canceladas/hora | $0.006 desperdício | $0.00001 desperdício | 99.8% |

---

## Implementação Técnica

### Server.py

```python
# Antes
@app.post("/query")
async def query_scans(request: QueryRequest):
    result = await query_service.query(...)
    return result

# Depois
@app.post("/query")
async def query_scans(request: Request, query_request: QueryRequest):
    # Verifica desconexão ANTES de processar
    if await request.is_disconnected():
        raise HTTPException(status_code=499, detail="Client disconnected")
    
    # Passa Request para query_service verificar durante processamento
    result = await query_service.query(..., request=request)
    return result
```

### QueryService.py

```python
async def query(
    self,
    question: str,
    request: Any = None  # FastAPI Request
) -> dict[str, Any]:
    
    # Checkpoint 1: Antes de operação cara
    if request and await request.is_disconnected():
        return {"answer": "Request cancelled", "sources": [], "confidence": 0.0}
    
    # Gera embedding ($0.000001)
    similar_scans = await self.embedding_service.search_similar(question)
    
    # Checkpoint 2: Antes de chamar LLM
    if request and await request.is_disconnected():
        return {"answer": "Request cancelled", "sources": [], "confidence": 0.0}
    
    # Chama LLM ($0.0006) - apenas se cliente ainda conectado
    answer = await self._generate_answer(question, context)
    
    return result
```

---

## Testando

### Teste Manual

```bash
# Terminal 1: Start servidor
uv run fackel serve

# Terminal 2: Request que cancela rápido
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Liste todas as vulnerabilidades", "max_scans": 10}' \
  --max-time 1

# Verifique logs do servidor:
# ✅ Deve mostrar: "Client disconnected before query processing"
# ✅ Não deve mostrar: Chamadas OpenAI subsequentes
```

### Teste Automatizado

```bash
# Script de teste completo
python test_request_cancellation.py

# Testa:
# 1. Cancelamento de query
# 2. Cancelamento de scan stream
# 3. Request normal (sem cancelamento)
```

---

## Status Codes HTTP

### 499 - Client Closed Request

Usamos código 499 (padrão nginx) para indicar que o cliente fechou a conexão:

```python
raise HTTPException(status_code=499, detail="Client disconnected")
```

**Por que 499?**
- É um código não-oficial mas amplamente reconhecido
- Indica claramente que foi o cliente que cancelou (não erro do servidor)
- Facilita debugging e métricas

**Alternativas consideradas:**
- 408 Request Timeout - implica timeout do servidor
- 444 No Response (nginx) - muito específico do nginx
- 499 Client Closed Request - ✅ escolhido

---

## Boas Práticas

### ✅ FAÇA

1. **Verifique em operações caras**:
   ```python
   # Antes de chamar APIs externas
   if await request.is_disconnected():
       return early_exit
   
   expensive_api_call()
   ```

2. **Verifique em loops**:
   ```python
   for item in large_dataset:
       if await request.is_disconnected():
           break
       process(item)
   ```

3. **Log apropriadamente**:
   ```python
   logger.info("Client disconnected, stopping processing")
   # Não use logger.error - não é erro do servidor
   ```

### ❌ NÃO FAÇA

1. **Não verifique em operações rápidas**:
   ```python
   # Operação < 100ms - overhead não vale a pena
   if await request.is_disconnected():  # ❌ Desnecessário
       return
   result = small_db_query()  # Rápido demais
   ```

2. **Não bloqueie verificação**:
   ```python
   # ❌ ERRADO - is_disconnected() pode bloquear
   while True:
       if await request.is_disconnected():  # Pode causar delay
           break
   
   # ✅ CORRETO - verifique periodicamente
   for i in range(1000):
       if i % 100 == 0 and await request.is_disconnected():
           break
   ```

3. **Não oculte erros reais**:
   ```python
   try:
       result = process()
   except Exception as e:
       if await request.is_disconnected():
           return  # ❌ Oculta erro real
       raise
   ```

---

## Monitoramento

### Métricas Importantes

```python
# Adicionar ao observability
metrics = {
    "requests_cancelled": Counter("http_requests_cancelled_total"),
    "cancelled_by_stage": Counter("http_requests_cancelled_by_stage"),
    "wasted_cost_prevented": Gauge("openai_wasted_cost_prevented_usd")
}

# Quando cancelado:
metrics["requests_cancelled"].inc()
metrics["cancelled_by_stage"].labels(stage="before_llm").inc()
metrics["wasted_cost_prevented"].set(0.0006)  # Custo LLM economizado
```

### Logs Estruturados

```python
logger.info(
    "Request cancelled",
    extra={
        "endpoint": "/query",
        "stage": "before_llm",
        "question_length": len(question),
        "cost_saved_usd": 0.0006
    }
)
```

---

## Limitações

1. **Verificação não é instantânea**: 
   - `is_disconnected()` pode levar alguns ms para detectar
   - Não podemos cancelar operação no meio (ex: meio de uma chamada LLM)

2. **Overhead mínimo**:
   - Cada verificação adiciona ~1-2ms
   - Use em pontos estratégicos, não em loops tight

3. **Sync vs Async**:
   - `is_disconnected()` é async, requer `await`
   - Não funciona em código síncrono

---

## Roadmap Futuro

### P1 - Próximas Semanas
- [ ] Adicionar cancelamento no LangGraph agent
- [ ] Métricas de custo economizado (Prometheus)
- [ ] Dashboard com requests canceladas

### P2 - Próximo Mês
- [ ] Timeout automático por tipo de operação
- [ ] Circuit breaker para clientes que cancelam muito
- [ ] Rate limiting baseado em histórico de cancelamentos

### P3 - Futuro
- [ ] Priorização de requests (menos provável cancelar = maior prioridade)
- [ ] Predição de cancelamento com ML
- [ ] Cache de resultados parciais

---

## Referências

- [FastAPI Request](https://fastapi.tiangolo.com/advanced/using-request-directly/)
- [HTTP 499 Status Code](https://httpstatuses.com/499)
- [AsyncIO Cancellation](https://docs.python.org/3/library/asyncio-task.html#asyncio.Task.cancel)
- [LangChain Callbacks](https://python.langchain.com/docs/modules/callbacks/)
