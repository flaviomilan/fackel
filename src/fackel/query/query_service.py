"""
Query Service — RAG (Retrieval-Augmented Generation) for scan results.

Enables natural language Q&A over persisted scans:
1. User asks: "Quais vulnerabilidades críticas foram encontradas?"
2. System embeds question
3. Search finds relevant scans semantically
4. LLM synthesizes answer from scan data

Design:
- Single Responsibility: Only handles Q&A logic
- Observability: Langfuse tracking
- Clean separation: Uses ScanRepository and EmbeddingService
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from fackel.core.observability import get_langfuse_handler, get_observability
from fackel.core.scan_repository import ScanRepository
from fackel.query.embeddings import ScanEmbeddingService


class QueryService:
    """Service for answering questions about scan results."""

    def __init__(
        self,
        scan_repo: ScanRepository,
        embedding_service: ScanEmbeddingService,
        llm_model: str = "gpt-4o-mini",
        temperature: float = 0.1
    ):
        self.scan_repo = scan_repo
        self.embedding_service = embedding_service
        self.llm = ChatOpenAI(
            model=llm_model,
            temperature=temperature,
            callbacks=get_langfuse_handler()
        )
        self.observability = get_observability()

    async def query(
        self,
        question: str,
        domain: str | None = None,
        max_scans: int = 3,
        request: Any = None  # FastAPI Request for cancellation check
    ) -> dict[str, Any]:
        """
        Answer a question about scan results.
        
        Args:
            question: Natural language question
            domain: Optional domain filter
            max_scans: Maximum number of scans to include in context
        
        Returns:
            {
                "answer": str,
                "sources": [{"scan_id": str, "domain": str, "timestamp": str}],
                "confidence": float
            }
        """
        # Track with observability
        span = self.observability.langfuse.span(
            name="query_scan",
            metadata={
                "question": question,
                "domain": domain,
                "max_scans": max_scans
            }
        )
        
        try:
            # Check if client disconnected before starting
            if request and await request.is_disconnected():
                span.end(metadata={"cancelled": True})
                return {
                    "answer": "Request cancelled by client",
                    "sources": [],
                    "confidence": 0.0
                }
            
            # Step 1: Semantic search for relevant scans
            similar_scans = await self.embedding_service.search_similar(
                query=question,
                limit=max_scans,
                domain=domain
            )
            
            # Check cancellation after embedding generation
            if request and await request.is_disconnected():
                span.end(metadata={"cancelled": True, "stage": "after_embedding"})
                return {
                    "answer": "Request cancelled by client",
                    "sources": [],
                    "confidence": 0.0
                }
            
            if not similar_scans:
                return {
                    "answer": "Não encontrei scans relevantes para responder essa pergunta.",
                    "sources": [],
                    "confidence": 0.0
                }
            
            # Step 2: Retrieve full scan data
            scan_contexts = []
            sources = []
            
            for result in similar_scans:
                scan = self.scan_repo.get_scan(result["scan_id"])
                if scan:
                    scan_contexts.append(scan)
                    sources.append({
                        "scan_id": scan["scan_id"],
                        "domain": scan["domain"],
                        "timestamp": scan["timestamp"].isoformat(),
                        "similarity": result["similarity_score"]
                    })
            
            # Step 3: Build context for LLM
            context = self._build_context(scan_contexts)
            
            # Check cancellation before expensive LLM call
            if request and await request.is_disconnected():
                span.end(metadata={"cancelled": True, "stage": "before_llm"})
                return {
                    "answer": "Request cancelled by client",
                    "sources": [],
                    "confidence": 0.0
                }
            
            # Step 4: Generate answer with LLM
            answer = await self._generate_answer(question, context)
            
            # Calculate confidence based on similarity scores
            avg_similarity = sum(s["similarity"] for s in sources) / len(sources)
            
            result = {
                "answer": answer,
                "sources": sources,
                "confidence": float(avg_similarity)
            }
            
            # Track success
            span.end(
                metadata={
                    "sources_found": len(sources),
                    "confidence": avg_similarity
                }
            )
            
            return result
            
        except Exception as e:
            span.end(metadata={"error": str(e)})
            raise

    def _build_context(self, scans: list[dict[str, Any]]) -> str:
        """Build context string from scan data."""
        context_parts = []
        
        for idx, scan in enumerate(scans, 1):
            report = scan["report"]
            
            context_parts.append(f"\n=== Scan {idx}: {scan['domain']} ===")
            context_parts.append(f"Data: {scan['timestamp'].isoformat()}")
            context_parts.append(f"Scan ID: {scan['scan_id']}")
            
            # Hosts
            if report.get("hosts"):
                context_parts.append(f"\nHosts ({len(report['hosts'])}):")
                for hostname, host in report["hosts"].items():
                    ip_str = f" ({host.get('ip')})" if host.get("ip") else ""
                    context_parts.append(f"  - {hostname}{ip_str}")
                    
                    # Services
                    for svc in host.get("services", []):
                        svc_str = f"    Port {svc['port']}/{svc['protocol']}: {svc.get('name', 'unknown')}"
                        if svc.get("product"):
                            svc_str += f" - {svc['product']}"
                            if svc.get("version"):
                                svc_str += f" {svc['version']}"
                        context_parts.append(svc_str)
                        
                        # CVEs
                        for cve in svc.get("cves", []):
                            cvss_str = f" (CVSS: {cve['cvss']})" if cve.get("cvss") else ""
                            context_parts.append(f"      🔴 {cve['cve_id']}{cvss_str}")
            
            # Findings
            if report.get("findings"):
                context_parts.append(f"\nFindings ({len(report['findings'])}):")
                for finding in report["findings"]:
                    severity_str = f" [{finding.get('severity', 'UNKNOWN')}]" if finding.get('severity') else ""
                    context_parts.append(f"  - {finding['title']}{severity_str}")
                    if finding.get("description"):
                        # Truncate long descriptions
                        desc = finding["description"][:200]
                        context_parts.append(f"    {desc}...")
            
            # People
            if report.get("people"):
                context_parts.append(f"\nPessoas ({len(report['people'])}):")
                for person in report["people"]:
                    role_str = f" - {person.get('role')}" if person.get('role') else ""
                    context_parts.append(f"  - {person['name']}{role_str}")
        
        return "\n".join(context_parts)

    async def _generate_answer(self, question: str, context: str) -> str:
        """Generate answer using LLM with ChatPromptTemplate (LCEL)."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """Você é um assistente especializado em segurança da informação e análise de vulnerabilidades.

Sua tarefa é responder perguntas sobre resultados de scans de segurança.

Regras:
1. Responda APENAS com base no contexto fornecido
2. Se a informação não estiver no contexto, diga "Não encontrei essa informação nos scans disponíveis"
3. Seja preciso e objetivo
4. Cite CVEs quando relevante
5. Organize a resposta de forma clara (use listas quando apropriado)
6. Se houver vulnerabilidades, classifique por severidade (Critical, High, Medium, Low)

Contexto dos scans:
{context}"""),
            ("user", "{question}")
        ])
        
        # LCEL chain composition
        chain = prompt | self.llm
        
        response = await chain.ainvoke({
            "context": context,
            "question": question
        })
        
        return response.content

    def query_sync(
        self,
        question: str,
        domain: str | None = None,
        max_scans: int = 3,
        request: Any = None
    ) -> dict[str, Any]:
        """Synchronous version of query."""
        import asyncio
        return asyncio.run(self.query(question, domain, max_scans, request))
