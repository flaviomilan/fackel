"""Shared wordlist discovery for scanning tools.

Both ffuf and feroxbuster need to locate a wordlist on disk.  This module
centralises the lookup logic so every scanner uses the same search order:
custom path → standard SecLists/dirb locations → bundled fallback.
"""

from __future__ import annotations

from pathlib import Path

# Standard SecLists / dirb locations checked in order.
DEFAULT_WORDLISTS: tuple[str, ...] = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
)

# Bundled minimal wordlist shipped with the package.
_BUNDLED = Path(__file__).resolve().parent / "wordlists" / "common.txt"


def find_wordlist(custom: str = "") -> str:
    """Return the first available wordlist path.

    Checks *custom* first, then standard SecLists/dirb locations,
    and finally falls back to the minimal wordlist bundled with the package.
    Returns an empty string when no wordlist can be found.
    """
    if custom:
        return custom

    for wl in DEFAULT_WORDLISTS:
        if Path(wl).is_file():
            return wl

    if _BUNDLED.is_file():
        return str(_BUNDLED)

    return ""
