"""Public document discovery via search-engine dorking.

Finds documents (PDF, Office files, etc.) that are publicly indexed for a
domain by issuing ``site:<domain> filetype:<ext>`` queries against DuckDuckGo.
Only the search engine is queried — the documents themselves are never
downloaded and the target is never touched — so this stays fully passive.

This is the discovery step that populates the ``DOCUMENT`` information type:
exposed reports, spreadsheets, and presentations are a common OSINT source of
internal names, software versions, and metadata.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import DDGS, TargetType, format_tool_output, guard_target

# Document extensions worth surfacing, ordered by intel value.
_FILETYPES: tuple[str, ...] = ("pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "csv", "txt")
_MAX_PER_FILETYPE = 8
_MAX_DOCUMENTS = 50


class DocumentSearchInput(BaseModel):
    """Input for public document discovery."""

    domain: str = Field(
        description=(
            "Domain to discover publicly indexed documents for (e.g. "
            "'example.com'). Returns document URLs with their filetype and "
            "title, harvested from search-engine results. The target is never "
            "contacted — only the search engine is queried."
        ),
    )


@tool(args_schema=DocumentSearchInput)
def document_search(domain: str) -> dict[str, Any]:
    """Discover a domain's publicly indexed documents via search-engine dorking.

    Issues ``site:<domain> filetype:<ext>`` queries (PDF, Office, CSV, …) and
    returns the document URLs with filetype and title. Pure passive OSINT — the
    documents are not downloaded and the target host is never contacted.
    """
    domain = guard_target(domain, "document_search", TargetType.DOMAIN)
    if DDGS is None:
        raise ToolException("document_search: duckduckgo-search not installed")

    documents: list[dict[str, str]] = []
    seen: set[str] = set()
    errors: list[str] = []
    try:
        ddgs_session = DDGS()
    except Exception as exc:
        raise ToolException(f"document_search: {exc}") from exc

    with ddgs_session as ddgs:
        for filetype in _FILETYPES:
            if len(documents) >= _MAX_DOCUMENTS:
                break
            query = f"site:{domain} filetype:{filetype}"
            # Per-query isolation: one filetype hitting a rate limit or transient
            # error must not discard the documents already collected.
            try:
                results = ddgs.text(query, max_results=_MAX_PER_FILETYPE)
            except Exception as exc:
                errors.append(f"{filetype}: {exc}")
                continue
            for r in results:
                url = str(r.get("href", "")).strip()
                if not url or url in seen:
                    continue
                seen.add(url)
                documents.append(
                    {
                        "url": url,
                        "title": str(r.get("title", "")).strip(),
                        "filetype": filetype,
                    }
                )
                if len(documents) >= _MAX_DOCUMENTS:
                    break

    # Only fail outright when every query errored and nothing was collected.
    if not documents and errors:
        raise ToolException(f"document_search: all queries failed ({'; '.join(errors)})")

    return format_tool_output(
        "document_search",
        domain,
        "ok",
        data={"domain": domain, "documents": documents, "count": len(documents)},
    )


document_search.handle_tool_error = True
