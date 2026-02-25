"""Shared HTTP client with connection pooling and automatic retries.

All tool modules should use :func:`get_session` instead of bare
``requests.get`` / ``requests.post`` calls.  The shared session provides:

- **TCP connection pooling** — reuses connections to the same host,
  avoiding repeated TLS handshakes and TCP slow-start.
- **Automatic retries** — retries on ``502``, ``503``, ``504`` and
  connection-level errors with exponential back-off.
- **Consistent User-Agent** — identifies the scanner across all tools.

Usage::

    from tools.http_client import get_session

    resp = get_session().get(url, timeout=15)
"""

from __future__ import annotations

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_USER_AGENT = "fackel-scanner/0.1"

_RETRY_STRATEGY = Retry(
    total=2,
    backoff_factor=1.0,
    status_forcelist=[502, 503, 504],
    allowed_methods=["GET", "POST", "HEAD"],
    raise_on_status=False,
)

_session: Session | None = None


def get_session() -> Session:
    """Return the module-level ``requests.Session`` (lazily created).

    The session is reused across all tool calls within the same process,
    keeping TCP connections alive through the underlying urllib3 pool.
    """
    global _session
    if _session is None:
        _session = Session()
        _session.headers["User-Agent"] = _USER_AGENT
        adapter = HTTPAdapter(max_retries=_RETRY_STRATEGY)
        _session.mount("https://", adapter)
        _session.mount("http://", adapter)
    return _session
