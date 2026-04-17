"""Natural-language query over a scan's knowledge graph.

Answers free-form questions ("which subdomains sit on CDN IPs?", "what
emails were found and were any breached?") by serialising the graph into a
compact context and asking an LLM to answer **strictly from that context**.
Backs the ``fackel ask`` command.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

from fackel.agents.config import build_llm
from fackel.persistence.graph_export import build_query_context
from fackel.persistence.store import InformationStore

_SYSTEM_PROMPT = (
    "You are a reconnaissance analyst answering questions about a target's "
    "external attack surface, using ONLY the knowledge graph provided below. "
    "The graph lists discovered entities (with confidence scores) and the "
    "relationships between them.\n\n"
    "Rules:\n"
    "- Answer strictly from the graph. Never invent or assume data.\n"
    "- If the graph does not contain the answer, say so plainly.\n"
    "- Be concise and cite the specific entities involved.\n"
    "- Prefer higher-confidence facts; note when a fact is low-confidence."
)


def answer_query(
    store: InformationStore,
    question: str,
    *,
    model_name: str | None = None,
) -> str:
    """Answer *question* about the scan's graph via the LLM.

    Returns the model's answer text. The graph context is built locally; the
    only network call is the LLM invocation.
    """
    context = build_query_context(store)
    llm = build_llm("query", model_name=model_name, temperature=0)
    response = llm.invoke(
        [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=f"{context}\n\nQUESTION: {question}"),
        ]
    )
    content = response.content
    return content if isinstance(content, str) else str(content)
