# Configuração Centralizada - Fackel

## Estrutura

```
src/fackel/config/
├── __init__.py          # Exports centralizados (PLAYBOOKS_PATH, etc.)
├── defaults.yaml        # Configurações padrão do sistema
└── playbooks.yaml       # Regras adaptativas de ferramentas
```

## Arquivos de Configuração

### 1. `defaults.yaml`

Configurações globais e valores padrão:

```yaml
llm:
  planner_model: gpt-4o-mini
  reporter_model: gpt-4o-mini
  temperature: 0.3

embeddings:
  model: text-embedding-3-small
  dimensions: 1536

vector_store:
  similarity_threshold: 0.6
  top_k_matches: 5

cache:
  redis:
    enabled: true
    ttl_playbook: 0
    ttl_query: 3600

tools:
  timeout_seconds: 300
  max_retries: 2

analysis:
  min_output_length: 50
  max_output_length: 32000
  skip_on_error: true
```

**Override via Environment Variables:**
- `LLM_MODEL`, `TEMPERATURE`
- `CACHE_TTL_PLAYBOOK`, `CACHE_TTL_QUERY`
- `TOOL_TIMEOUT`, `TOOL_MAX_RETRIES`

### 2. `playbooks.yaml`

Regras de seleção adaptativa de ferramentas baseadas em tecnologias detectadas.

Cada playbook define:
- **name**: Identificador único
- **description**: Descrição semântica (usada no embedding)
- **signals.any**: Lista de padrões para matching
- **tools**: Ferramentas a enfileirar + motivos

Ver [docs/vector_store_playbooks.md](vector_store_playbooks.md) para detalhes completos.

## Uso no Código

### Importar Paths Centralizados

```python
from fackel.config import PLAYBOOKS_PATH, CONFIG_DIR

# Carregar playbooks
with open(PLAYBOOKS_PATH) as f:
    data = yaml.safe_load(f)

# Outros configs
defaults_path = CONFIG_DIR / "defaults.yaml"
```

### Loader de Configuração (Futuro)

```python
from fackel.config import load_config

config = load_config()  # Carrega defaults.yaml + overrides do .env
print(config["llm"]["planner_model"])
```

## Migração de Configurações

### Movidos para `config/`:
- ✅ `agents/playbooks.yaml` → `config/playbooks.yaml`

### A Migrar (Futuro):
- [ ] Hardcoded LLM models → `defaults.yaml`
- [ ] Cache TTL defaults → `defaults.yaml`
- [ ] Tool timeouts → `defaults.yaml`
- [ ] Thresholds de similaridade → `defaults.yaml`

## Extensões Futuras

- [ ] Loader YAML centralizado com merge de múltiplos arquivos
- [ ] Validação de schemas com Pydantic
- [ ] Hot-reload de configurações
- [ ] CLI para visualizar/editar configs: `fackel config show/set`
- [ ] Profiles por ambiente (dev/staging/prod)
