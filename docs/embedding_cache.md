# Embedding Cache - Redis

## Overview
Sistema de cache para embeddings vetoriais usando Redis, reduzindo custos e latência das chamadas à API do OpenAI.

## Arquitetura

### Separação de Responsabilidades
- `core/embedding_cache.py`: Infraestrutura (Redis client, serialização)
- `agents/vector_store.py`: Domínio (matching semântico, playbooks)

### Cache Key Strategy
```
fackel:embedding:<sha256-hash-do-texto>
```
Keys são content-addressable: mesmo texto = mesma key = hit no cache.

### TTL (Time-to-Live)
- **Playbooks**: sem expiração (conteúdo estático)
- **Query embeddings**: 1 hora (conteúdo dinâmico)

## Configuração

### Variáveis de Ambiente (.env)
```bash
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=  # opcional
```

### Docker Compose
```bash
# Subir Redis
docker-compose -f docker-compose.redis.yml up -d

# Verificar status
docker ps | grep fackel-redis

# Logs
docker logs fackel-redis

# Parar
docker-compose -f docker-compose.redis.yml down
```

## Gerenciamento

### CLI Utilitário
```bash
# Estatísticas do cache
python manage_cache.py stats

# Output:
# 📊 Cache Statistics:
#    Total fackel embeddings: 12
#    Cache hits: 245
#    Cache misses: 18

# Limpar cache (requer confirmação)
python manage_cache.py clear

# Testar funcionamento
python manage_cache.py test
```

### Redis CLI (manual)
```bash
# Conectar
redis-cli

# Ver todas as keys do Fackel
KEYS fackel:embedding:*

# Ver estatísticas
INFO stats

# Limpar tudo (CUIDADO!)
FLUSHDB
```

## Comportamento

### Cache Hit
1. Texto → SHA256 → Key
2. Redis GET(key)
3. Deserialização (pickle → numpy array)
4. Retorna embedding

### Cache Miss
1. Texto → OpenAI API (embed_query)
2. Redis SET(key, embedding)
3. Retorna embedding

### Fallback Gracioso
Se Redis indisponível:
- Log warning
- Prossegue sem cache
- Embeddings gerados a cada carga

## Performance

### Benefícios
- **Custo**: ~100x mais barato que API calls repetidas
- **Latência**: ~50-100ms (cache) vs ~500-1000ms (API)
- **Rate Limits**: elimina hits desnecessários

### Métricas Esperadas
Para 10 playbooks e 100 scans:
- Playbook embeddings: 10 API calls (uma vez)
- Query embeddings: ~100 API calls (sem cache) → ~10-20 (com cache + TTL)
- Economia: ~85-90%

## Troubleshooting

### Redis não conecta
```bash
# Verificar se está rodando
docker ps | grep redis

# Testar conexão
redis-cli ping
# Resposta esperada: PONG

# Verificar logs
docker logs fackel-redis
```

### Cache não funciona
```python
from fackel.core.embedding_cache import EmbeddingCache

cache = EmbeddingCache()
print(cache.available)  # Deve ser True
```

### Limpar cache corrompido
```bash
# Via CLI
python manage_cache.py clear

# Via Redis
redis-cli
> KEYS fackel:embedding:*
> DEL fackel:embedding:<key>
```

## Extensões Futuras
- [ ] Invalidação automática quando playbooks mudam (watch file)
- [ ] Métricas expostas via endpoint (hit rate, latency)
- [ ] Suporte para múltiplos modelos de embedding
- [ ] Compression (zlib/lz4) para economizar memória
- [ ] Replicação Redis para HA
