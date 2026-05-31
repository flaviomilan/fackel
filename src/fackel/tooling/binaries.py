"""External binary discovery for tool availability gating.

Tools that wrap CLI binaries (`nmap`, `nuclei`, etc.) call
``require_binary(...)`` lazily at execution time.  This module lets
agent ``build()`` functions check binary availability *eagerly* —
before the LLM is offered a tool it cannot actually run — by
inspecting ``shutil.which``.

The mapping below mirrors every ``require_binary("<bin>", "<tool>")``
call in ``src/tools/**``; keep it in sync.
"""

from __future__ import annotations

import shutil
from typing import Any

TOOL_BINARIES: dict[str, str] = {
    "amass_enum": "amass",
    "cloudbrute_enum": "cloudbrute",
    "corsy_scan": "corsy",
    "dalfox_scan": "dalfox",
    "dnsx_resolve": "dnsx",
    "feroxbuster_scan": "feroxbuster",
    "ffuf_scan": "ffuf",
    "gau_urls": "gau",
    "katana_crawl": "katana",
    "linkfinder_extract": "linkfinder",
    "naabu_scan": "naabu",
    "nmap_port_scan": "nmap",
    "nuclei_scan": "nuclei",
    "open_redirect_scan": "nuclei",
    "paramspider_crawl": "paramspider",
    "s3scanner_scan": "s3scanner",
    "sqlmap_scan": "sqlmap",
    "ssrf_detect": "nuclei",
    "ssti_scan": "nuclei",
    "subfinder_enum": "subfinder",
    "subzy_check": "subzy",
    "testssl_scan": "testssl.sh",
    "trufflehog_scan": "trufflehog",
    "wafw00f_detect": "wafw00f",
    "whatweb_scan": "whatweb",
    "wpscan_scan": "wpscan",
}


def available_binaries(
    tools: list[Any],
) -> tuple[list[Any], list[tuple[str, str]]]:
    """Partition *tools* by external binary availability on ``PATH``.

    Returns ``(available, missing)`` where *missing* contains
    ``(tool_name, binary_name)`` tuples for tools whose backing
    CLI is not installed.  Tools without a registered binary
    (pure-Python wrappers) are always considered available.
    """
    available: list[Any] = []
    missing: list[tuple[str, str]] = []
    for tool in tools:
        name = getattr(tool, "name", "")
        binary = TOOL_BINARIES.get(name)
        if binary is None or shutil.which(binary):
            available.append(tool)
        else:
            missing.append((name, binary))
    return available, missing
