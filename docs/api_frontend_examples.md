"""
Frontend Integration Examples

JavaScript/TypeScript examples for integrating with Fackel API.
"""

# =============================================================================
# React/Next.js Example
# =============================================================================

"""
// types.ts - TypeScript interfaces matching API models

export interface QueryRequest {
  question: string;
  domain?: string;
  max_scans?: number;
}

export interface ScanSource {
  scan_id: string;
  domain: string;
  timestamp: string;
  similarity: number;
}

export interface QueryResponse {
  answer: string;
  sources: ScanSource[];
  confidence: number;
  question: string;
  processing_time_ms?: number;
}

export interface ScanSummary {
  scan_id: string;
  domain: string;
  timestamp: string;
  host_count: number;
  service_count: number;
  finding_count: number;
  cve_count: number;
  metadata: Record<string, any>;
}

export interface ScanListResponse {
  scans: ScanSummary[];
  total: number;
  limit: number;
  skip: number;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  features: {
    scan_streaming: boolean;
    query_system: boolean;
    scan_persistence: boolean;
  };
}

// api.ts - API client

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export class FackelAPI {
  private baseURL: string;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  // Health check
  async health(): Promise<HealthResponse> {
    const response = await fetch(`${this.baseURL}/health`);
    if (!response.ok) throw new Error('Health check failed');
    return response.json();
  }

  // Query system - Ask questions about scans
  async query(request: QueryRequest): Promise<QueryResponse> {
    const response = await fetch(`${this.baseURL}/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Query failed');
    }

    return response.json();
  }

  // List scans
  async listScans(
    domain?: string,
    limit: number = 50,
    skip: number = 0
  ): Promise<ScanListResponse> {
    const params = new URLSearchParams({
      limit: limit.toString(),
      skip: skip.toString(),
    });
    
    if (domain) {
      params.append('domain', domain);
    }

    const response = await fetch(`${this.baseURL}/scans?${params}`);
    if (!response.ok) throw new Error('Failed to list scans');
    return response.json();
  }

  // Get scan details
  async getScan(scanId: string): Promise<any> {
    const response = await fetch(`${this.baseURL}/scans/${scanId}`);
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Scan not found');
      }
      throw new Error('Failed to get scan');
    }
    return response.json();
  }

  // Get latest scan for domain
  async getLatestScan(domain: string): Promise<any> {
    const response = await fetch(`${this.baseURL}/scans/domain/${domain}/latest`);
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(`No scans found for ${domain}`);
      }
      throw new Error('Failed to get latest scan');
    }
    return response.json();
  }

  // Stream scan (Server-Sent Events)
  streamScan(
    domain: string,
    active: boolean = false,
    onEvent: (event: any) => void,
    onError: (error: Error) => void,
    onComplete: () => void
  ): EventSource {
    const params = new URLSearchParams({
      domain,
      active: active.toString(),
    });

    const eventSource = new EventSource(
      `${this.baseURL}/scan/stream?${params}`
    );

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onEvent(data);
      } catch (e) {
        console.error('Failed to parse SSE event:', e);
      }
    };

    eventSource.addEventListener('close', () => {
      eventSource.close();
      onComplete();
    });

    eventSource.onerror = (error) => {
      eventSource.close();
      onError(new Error('Stream connection failed'));
    };

    return eventSource;
  }
}

// React Hook Example
// hooks/useFackelAPI.ts

import { useState, useCallback } from 'react';
import { FackelAPI, QueryResponse, ScanListResponse } from '../api';

const api = new FackelAPI();

export function useQuery() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QueryResponse | null>(null);

  const query = useCallback(async (question: string, domain?: string) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await api.query({ question, domain });
      setResult(response);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query failed');
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { query, loading, error, result };
}

export function useScans() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanListResponse | null>(null);

  const fetchScans = useCallback(async (domain?: string, limit = 50, skip = 0) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await api.listScans(domain, limit, skip);
      setScans(response);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans');
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { fetchScans, loading, error, scans };
}

// React Component Example
// components/QueryInterface.tsx

import React, { useState } from 'react';
import { useQuery } from '../hooks/useFackelAPI';

export function QueryInterface() {
  const [question, setQuestion] = useState('');
  const { query, loading, error, result } = useQuery();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim()) return;
    
    await query(question);
  };

  return (
    <div className="query-interface">
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Pergunte sobre os scans..."
          disabled={loading}
        />
        <button type="submit" disabled={loading || !question.trim()}>
          {loading ? 'Processando...' : 'Perguntar'}
        </button>
      </form>

      {error && (
        <div className="error">
          ❌ Erro: {error}
        </div>
      )}

      {result && (
        <div className="result">
          <div className="answer">
            <h3>Resposta:</h3>
            <p>{result.answer}</p>
          </div>

          <div className="metadata">
            <span>Confiança: {(result.confidence * 100).toFixed(1)}%</span>
            {result.processing_time_ms && (
              <span>Tempo: {result.processing_time_ms.toFixed(0)}ms</span>
            )}
          </div>

          {result.sources.length > 0 && (
            <div className="sources">
              <h4>Fontes ({result.sources.length}):</h4>
              <ul>
                {result.sources.map((source) => (
                  <li key={source.scan_id}>
                    <strong>{source.domain}</strong>
                    <span>Similaridade: {(source.similarity * 100).toFixed(1)}%</span>
                    <span>{new Date(source.timestamp).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Streaming Scan Component
// components/ScanStream.tsx

import React, { useState, useCallback } from 'react';
import { FackelAPI } from '../api';

const api = new FackelAPI();

export function ScanStream() {
  const [domain, setDomain] = useState('');
  const [events, setEvents] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [eventSource, setEventSource] = useState<EventSource | null>(null);

  const startScan = useCallback(() => {
    if (!domain.trim()) return;

    setScanning(true);
    setEvents([]);

    const source = api.streamScan(
      domain,
      false,
      (event) => {
        setEvents((prev) => [...prev, event]);
      },
      (error) => {
        console.error('Scan error:', error);
        setScanning(false);
      },
      () => {
        setScanning(false);
      }
    );

    setEventSource(source);
  }, [domain]);

  const stopScan = useCallback(() => {
    if (eventSource) {
      eventSource.close();
      setEventSource(null);
    }
    setScanning(false);
  }, [eventSource]);

  return (
    <div className="scan-stream">
      <div className="controls">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          disabled={scanning}
        />
        {!scanning ? (
          <button onClick={startScan} disabled={!domain.trim()}>
            Iniciar Scan
          </button>
        ) : (
          <button onClick={stopScan}>Parar</button>
        )}
      </div>

      <div className="events">
        {events.map((event, idx) => (
          <div key={idx} className={`event event-${event.type}`}>
            <span className="type">{event.type}</span>
            <span className="timestamp">{event.timestamp}</span>
            <pre>{JSON.stringify(event.details, null, 2)}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}
"""

# =============================================================================
# Vue.js Example
# =============================================================================

"""
// composables/useFackel.ts

import { ref, Ref } from 'vue';

interface QueryResponse {
  answer: string;
  sources: any[];
  confidence: number;
  question: string;
}

export function useFackelQuery() {
  const loading = ref(false);
  const error: Ref<string | null> = ref(null);
  const result: Ref<QueryResponse | null> = ref(null);

  async function query(question: string, domain?: string) {
    loading.value = true;
    error.value = null;

    try {
      const response = await fetch('http://localhost:8000/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, domain }),
      });

      if (!response.ok) {
        throw new Error('Query failed');
      }

      result.value = await response.json();
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'Unknown error';
    } finally {
      loading.value = false;
    }
  }

  return { query, loading, error, result };
}
"""

# =============================================================================
# Vanilla JavaScript/Fetch Example
# =============================================================================

"""
// Simple fetch example

async function askQuestion(question, domain = null) {
  const response = await fetch('http://localhost:8000/query', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      question: question,
      domain: domain,
      max_scans: 3
    })
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const data = await response.json();
  
  console.log('Answer:', data.answer);
  console.log('Confidence:', (data.confidence * 100).toFixed(1) + '%');
  console.log('Sources:', data.sources);
  
  return data;
}

// Usage
askQuestion('Quais vulnerabilidades críticas existem?')
  .then(result => {
    console.log(result);
  })
  .catch(error => {
    console.error('Error:', error);
  });

// List scans
async function listScans(domain = null, limit = 50) {
  const params = new URLSearchParams({ limit: limit.toString() });
  if (domain) params.append('domain', domain);

  const response = await fetch(`http://localhost:8000/scans?${params}`);
  const data = await response.json();

  console.log(`Found ${data.total} scans`);
  data.scans.forEach(scan => {
    console.log(`- ${scan.domain}: ${scan.cve_count} CVEs, ${scan.finding_count} findings`);
  });

  return data;
}

// Get scan details
async function getScanDetails(scanId) {
  const response = await fetch(`http://localhost:8000/scans/${scanId}`);
  
  if (response.status === 404) {
    throw new Error('Scan not found');
  }

  const data = await response.json();
  return data;
}

// Stream scan with SSE
function streamScan(domain, onEvent, onComplete) {
  const eventSource = new EventSource(
    `http://localhost:8000/scan/stream?domain=${domain}&active=false`
  );

  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    onEvent(data);
  };

  eventSource.addEventListener('close', () => {
    eventSource.close();
    onComplete();
  });

  eventSource.onerror = () => {
    eventSource.close();
    console.error('Stream error');
  };

  return eventSource;
}

// Usage
const stream = streamScan(
  'example.com',
  (event) => {
    console.log('Event:', event.type, event);
    if (event.type === 'partial_report') {
      console.log('Partial analysis:', event.details.analysis);
    }
  },
  () => {
    console.log('Scan complete!');
  }
);

// To stop: stream.close();
"""

# =============================================================================
# Python Requests Example
# =============================================================================

"""
import requests

API_BASE = "http://localhost:8000"

# Health check
response = requests.get(f"{API_BASE}/health")
health = response.json()
print(f"Service: {health['service']} v{health['version']}")
print(f"Query system available: {health['features']['query_system']}")

# Ask a question
query_request = {
    "question": "Quais vulnerabilidades críticas foram encontradas?",
    "domain": None,  # Optional filter
    "max_scans": 3
}

response = requests.post(f"{API_BASE}/query", json=query_request)
result = response.json()

print(f"Answer: {result['answer']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Sources: {len(result['sources'])}")

for source in result['sources']:
    print(f"  - {source['domain']} (similarity: {source['similarity']:.2f})")

# List scans
params = {"domain": "example.com", "limit": 10}
response = requests.get(f"{API_BASE}/scans", params=params)
scans = response.json()

print(f"Total scans: {scans['total']}")
for scan in scans['scans']:
    print(f"  {scan['domain']}: {scan['cve_count']} CVEs")

# Get scan details
scan_id = scans['scans'][0]['scan_id']
response = requests.get(f"{API_BASE}/scans/{scan_id}")
details = response.json()
print(f"Scan: {details['domain']} at {details['timestamp']}")
print(f"Hosts: {details['host_count']}, Services: {details['service_count']}")
"""
