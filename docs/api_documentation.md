# API Documentation - Frontend Integration

Complete guide for integrating Fackel API with web frontends.

## 📋 Table of Contents

1. [Base URL & Authentication](#base-url--authentication)
2. [Endpoints](#endpoints)
3. [Request/Response Models](#requestresponse-models)
4. [Frontend Integration](#frontend-integration)
5. [Error Handling](#error-handling)
6. [Examples](#examples)

---

## Base URL & Authentication

**Base URL**: `http://localhost:8000` (development)

**Authentication**: Currently none (add JWT/API keys for production)

**CORS**: Enabled for all origins in development

---

## Endpoints

### Health Check

**GET** `/health`

Check API status and feature availability.

**Response**: `HealthResponse`
```json
{
  "status": "ok",
  "service": "fackel-agent",
  "version": "2.0.0",
  "features": {
    "scan_streaming": true,
    "query_system": true,
    "scan_persistence": true
  }
}
```

---

### Query System - Ask Questions

**POST** `/query`

Ask natural language questions about scan results.

**Request Body**: `QueryRequest`
```json
{
  "question": "Quais vulnerabilidades críticas foram encontradas?",
  "domain": "example.com",  // Optional filter
  "max_scans": 3            // Context size (1-10)
}
```

**Response**: `QueryResponse`
```json
{
  "answer": "Foram encontradas 3 vulnerabilidades críticas:\n\n1. CVE-2021-23017 (CVSS 7.5) - nginx 1.18.0\n   Host: web.example.com\n   Descrição: Memory corruption vulnerability...",
  "sources": [
    {
      "scan_id": "abc123-def456",
      "domain": "example.com",
      "timestamp": "2026-02-08T10:30:00Z",
      "similarity": 0.87
    }
  ],
  "confidence": 0.87,
  "question": "Quais vulnerabilidades críticas foram encontradas?",
  "processing_time_ms": 2340.5
}
```

**Status Codes**:
- `200` - Success
- `503` - Query system unavailable (MongoDB/OpenAI not configured)
- `500` - Processing error

---

### List Scans

**GET** `/scans`

List all scans with optional filters.

**Query Parameters**:
- `domain` (optional): Filter by domain
- `limit` (default: 50, max: 100): Results per page
- `skip` (default: 0): Pagination offset

**Example**: `/scans?domain=example.com&limit=20&skip=0`

**Response**: `ScanListResponse`
```json
{
  "scans": [
    {
      "scan_id": "abc123",
      "domain": "example.com",
      "timestamp": "2026-02-08T10:30:00Z",
      "host_count": 5,
      "service_count": 23,
      "finding_count": 12,
      "cve_count": 8,
      "metadata": {
        "active_scan": true,
        "critical_findings": 3
      }
    }
  ],
  "total": 1,
  "limit": 50,
  "skip": 0
}
```

---

### Get Scan Details

**GET** `/scans/{scan_id}`

Get complete details of a specific scan.

**Response**: `ScanDetailResponse`
```json
{
  "scan_id": "abc123",
  "domain": "example.com",
  "timestamp": "2026-02-08T10:30:00Z",
  "host_count": 5,
  "service_count": 23,
  "finding_count": 12,
  "cve_count": 8,
  "metadata": {...},
  "report": {
    "domain": "example.com",
    "hosts": {...},
    "findings": [...],
    "services": [...],
    "people": [...]
  }
}
```

**Status Codes**:
- `200` - Success
- `404` - Scan not found
- `500` - Server error

---

### Get Latest Scan

**GET** `/scans/domain/{domain}/latest`

Get the most recent scan for a specific domain.

**Example**: `/scans/domain/example.com/latest`

**Response**: `ScanDetailResponse` (same as above)

**Status Codes**:
- `200` - Success
- `404` - No scans found for domain
- `500` - Server error

---

### Stream Scan (SSE)

**GET** `/scan/stream`

Start a new scan and stream progress via Server-Sent Events.

**Query Parameters**:
- `domain` (required): Target domain
- `active` (default: false): Enable active scanning tools

**Example**: `/scan/stream?domain=example.com&active=true`

**Response**: Server-Sent Events stream

**Event Types**:

1. **step_update**: Tool execution progress
```json
{
  "type": "step_update",
  "step": "run",
  "timestamp": "2026-02-08T10:31:00",
  "details": {
    "last_tool": "nmap_port_scan",
    "completed_count": 3
  }
}
```

2. **partial_report**: Incremental analysis
```json
{
  "type": "partial_report",
  "step": "run",
  "timestamp": "2026-02-08T10:31:05",
  "details": {
    "tool": "nmap_port_scan",
    "analysis": "Port scan revealed 5 open ports...",
    "timestamp": "2026-02-08T10:31:05"
  }
}
```

3. **close**: Stream complete
```json
{
  "type": "close"
}
```

4. **error**: Stream error
```json
{
  "type": "error",
  "message": "Tool execution failed: ..."
}
```

---

## Request/Response Models

### QueryRequest

```typescript
interface QueryRequest {
  question: string;      // Min: 5 chars, Max: 500 chars
  domain?: string;       // Optional domain filter
  max_scans?: number;    // 1-10, default: 3
}
```

### QueryResponse

```typescript
interface QueryResponse {
  answer: string;                  // LLM-generated answer
  sources: ScanSource[];           // Scans used for context
  confidence: number;              // 0.0 to 1.0
  question: string;                // Original question
  processing_time_ms?: number;     // Query latency
}

interface ScanSource {
  scan_id: string;
  domain: string;
  timestamp: string;               // ISO 8601
  similarity: number;              // 0.0 to 1.0
}
```

### ScanSummary

```typescript
interface ScanSummary {
  scan_id: string;
  domain: string;
  timestamp: string;               // ISO 8601 (Date object when parsed)
  host_count: number;
  service_count: number;
  finding_count: number;
  cve_count: number;
  metadata: Record<string, any>;
}
```

---

## Frontend Integration

### React/Next.js

```typescript
// API Client
import { useState } from 'react';

const API_BASE = 'http://localhost:8000';

export function useQuery() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function query(question: string) {
    setLoading(true);
    
    const response = await fetch(`${API_BASE}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question })
    });

    const data = await response.json();
    setResult(data);
    setLoading(false);
  }

  return { query, loading, result };
}

// Component
export function QueryInterface() {
  const { query, loading, result } = useQuery();
  const [question, setQuestion] = useState('');

  return (
    <div>
      <input
        value={question}
        onChange={(e) => setQuestion(e.target.value)}
        placeholder="Pergunte sobre os scans..."
      />
      <button onClick={() => query(question)} disabled={loading}>
        {loading ? 'Processando...' : 'Perguntar'}
      </button>

      {result && (
        <div>
          <p>{result.answer}</p>
          <span>Confiança: {(result.confidence * 100).toFixed(1)}%</span>
        </div>
      )}
    </div>
  );
}
```

### Vue.js

```typescript
// composables/useFackel.ts
import { ref } from 'vue';

export function useFackelQuery() {
  const loading = ref(false);
  const result = ref(null);

  async function query(question: string) {
    loading.value = true;
    
    const response = await fetch('http://localhost:8000/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question })
    });

    result.value = await response.json();
    loading.value = false;
  }

  return { query, loading, result };
}
```

### Vanilla JavaScript

```javascript
async function askQuestion(question) {
  const response = await fetch('http://localhost:8000/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question })
  });

  return await response.json();
}

// Usage
askQuestion('Quais CVEs existem?').then(result => {
  console.log(result.answer);
});
```

---

## Error Handling

### Standard Error Response

```json
{
  "detail": "Error message"
}
```

### Common Errors

| Status | Error | Solution |
|--------|-------|----------|
| 400 | Invalid request | Check request body schema |
| 404 | Scan not found | Verify scan_id exists |
| 503 | Query system unavailable | Check MongoDB/OpenAI config |
| 500 | Internal server error | Check logs |

### Client-Side Error Handling

```typescript
async function safeQuery(question: string) {
  try {
    const response = await fetch('http://localhost:8000/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Query failed');
    }

    return await response.json();
  } catch (error) {
    console.error('Query error:', error);
    // Show user-friendly message
    alert('Não foi possível processar sua pergunta. Tente novamente.');
    throw error;
  }
}
```

---

## Examples

See complete examples in [api_frontend_examples.md](api_frontend_examples.md):

- React/Next.js full implementation
- Vue.js composables
- Vanilla JavaScript
- Python requests
- SSE streaming integration

---

## Running the API

```bash
# Start MongoDB
docker-compose up -d mongodb

# Set environment variables
export OPENAI_API_KEY="sk-..."
export LANGFUSE_PUBLIC_KEY="pk-..."  # Optional
export LANGFUSE_SECRET_KEY="sk-..."  # Optional

# Start API server
uvicorn src.fackel.server:app --reload --host 0.0.0.0 --port 8000
```

**Interactive Docs**: http://localhost:8000/docs (Swagger UI)

---

## Production Considerations

1. **Authentication**: Add JWT or API key authentication
2. **Rate Limiting**: Implement rate limiting per IP/user
3. **CORS**: Lock down allowed origins
4. **HTTPS**: Use TLS in production
5. **Monitoring**: Add metrics (Prometheus, Datadog)
6. **Caching**: Cache frequent queries (Redis)
7. **Pagination**: Implement cursor-based pagination for large datasets
8. **Timeouts**: Set reasonable timeouts for LLM calls
9. **Error Logging**: Structured logging (Sentry, Rollbar)
10. **API Versioning**: Add `/v1/` prefix for versioning

---

## Support

**Documentation**: [docs/query_system.md](query_system.md)  
**Quick Start**: [QUERY_QUICKSTART.md](../QUERY_QUICKSTART.md)  
**Examples**: [examples/query_service_example.py](../examples/query_service_example.py)
