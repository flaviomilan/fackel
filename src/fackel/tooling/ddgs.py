"""Lazy import for the DuckDuckGo search SDK.

Tries ``ddgs`` first (newer package name), then ``duckduckgo_search``
(legacy).  Assigns ``None`` when neither is installed so callers can
degrade gracefully.
"""

from __future__ import annotations

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None  # type: ignore[assignment,misc]
