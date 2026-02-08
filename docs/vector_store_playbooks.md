# Vector Store e Playbooks - Documentação

## Overview
Sistema de seleção adaptativa de ferramentas usando embeddings semânticos e playbooks externos.

## Arquitetura

### 1. Vector Store (`vector_store.py`)
- Carrega playbooks de YAML e gera embeddings (OpenAI text-embedding-3-small)
- **Cache Redis**: embeddings persistidos para evitar recomputação e economizar tokens
- Usa busca semântica (cosine similarity) para matching de sinais → ferramentas
- Fallback para matching por keywords se embeddings falharem
- Threshold padrão: 0.6 (ajustável)

### 1.1 Embedding Cache (`core/embedding_cache.py`)
- Cache baseado em Redis com keys content-addressable (SHA256 do texto)
- TTL configurável: playbooks sem expiração, queries com 1h
- Fallback gracioso: se Redis indisponível, funciona sem cache
- Configuração via variáveis de ambiente (`REDIS_HOST`, `REDIS_PORT`, etc.)

### 2. Playbooks (`config/playbooks.yaml`)
Estrutura:
```yaml
- name: <nome_da_regra>
  description: <descrição semântica>
  signals:
    any:
      - <padrão1>
      - <padrão2>
  tools:
    - name: <nome_ferramenta>
      reason: <motivo para enfileirar>
```

Playbooks cobrem:
- GraphQL, WordPress, Node.js, React/SPA
- REST APIs, AWS, Cloudflare, Jenkins
- Bancos expostos (MongoDB, MySQL, Redis, Postgres)
- Superfície web (HTTP/HTTPS)

### 3. Policy Engine (`policy.py`)
- Extrai sinais do estado (evidências, serviços, findings, analysis_log)
- Consulta vector store (semantic matching)
- Aplica heurísticas built-in como fallback
- Retorna `ToolProposal` com `{tool, rule, reason}`

### 4. Integração no Agente (`graph_agent.py`)
Após cada ferramenta bem-sucedida:
1. Policy extrai sinais do estado atualizado
2. Vector store faz matching semântico
3. Propostas filtradas contra registry
4. Ferramentas enfileiradas em `state.plan`
5. Decisões registradas em `state.decisions`
6. Eventos de policy emitidos no stream

## Eventos de Stream

### `step_update` (run)
```json
{
  "type": "step_update",
  "step": "run",
  "timestamp": "...",
  "details": {
    "last_tool": "httpx_scan",
    "completed_count": 5
  }
}
```

### `partial_report`
```json
{
  "type": "partial_report",
  "step": "run",
  "timestamp": "...",
  "details": {
    "tool": "httpx_scan",
    "analysis": "Detected Nginx 1.18...",
    "timestamp": "..."
  }
}
```

### `policy_decision` (novo)
```json
{
  "type": "policy_decision",
  "step": "run",
  "timestamp": "...",
  "details": {
    "decisions": [
      {
        "tool": "nuclei_scan",
        "rule": "wordpress",
        "reason": "WordPress indicators: evidence:httpx_scan"
      },
      {
        "tool": "wafw00f_detect",
        "rule": "web_surface",
        "reason": "HTTP service detected; confirm WAF presence"
      }
    ],
    "tools_added": ["nuclei_scan", "wafw00f_detect"]
  }
}
```

### `final_report`
```json
{
  "type": "final_report",
  "step": "report",
  "timestamp": "...",
  "details": {
    "final_report": "# Relatório...",
    "summary": "### Score Geral...",
    "analysis_log": [...]
  }
}
```

## Configuração

### Variáveis de Ambiente
- `OPENAI_API_KEY`: necessária para embeddings
- `FACKEL_PLAYBOOKS_PATH`: caminho customizado para playbooks (opcional)
- `REDIS_HOST`: host do Redis (default: localhost)
- `REDIS_PORT`: porta do Redis (default: 6379)
- `REDIS_DB`: database do Redis (default: 0)
- `REDIS_PASSWORD`: senha do Redis (opcional)

### Setup Redis
```bash
# Docker Compose (recomendado)
docker-compose -f docker-compose.redis.yml up -d

# Docker manual
docker run -d --name fackel-redis -p 6379:6379 redis:7-alpine

# Ou local
brew install redis  # macOS
sudo apt install redis-server  # Ubuntu
```

### Gerenciamento do Cache
```bash
# Ver estatísticas
python manage_cache.py stats

# Limpar cache (requer confirmação)
python manage_cache.py clear

# Testar cache
python manage_cache.py test
```

### Customização de Playbooks
Edite `src/fackel/config/playbooks.yaml` para adicionar novas regras:
1. Adicione sinais semânticos no campo `signals.any`
2. Liste ferramentas e motivos em `tools`
3. O vector store automaticamente gera embeddings no próximo load

**Observação**: Todas as configurações centralizadas estão em `src/fackel/config/`:
- `playbooks.yaml`: Regras adaptativas de seleção de ferramentas
- `defaults.yaml`: Configurações padrão (LLM, cache, thresholds)

### Threshold de Similaridade
Ajuste em `VectorPlaybookStore.match()`:
```python
store.match(signals, threshold=0.7, top_k=3)
```

## Extensões Futuras
- [ ] Suportar playbooks por scan mode (passive/active)
- [ ] Prioridades e parâmetros customizados por playbook
- [ ] API para adicionar playbooks dinamicamente
- [ ] Métricas de eficácia (hit rate, false positives)
- [ ] Invalidação inteligente de cache quando playbooks mudam
