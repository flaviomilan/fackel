"""Tool output sanitizer — defence against prompt injection via tool responses.

External services can return adversarial content designed to manipulate the
LLM when injected as ToolMessage context.  This module detects and strips
known prompt-injection patterns from raw tool output strings **before** they
are passed to the agent as observations.

Usage::

    from fackel.tooling.output_sanitizer import sanitize_tool_output

    clean = sanitize_tool_output(raw_output, max_bytes=50_000)

Defence layers:

1. **Size limit** — truncates oversized outputs to prevent context-window
   flooding (default 50 KB).
2. **Pattern stripping** — removes common prompt-injection payloads
   (``ignore previous instructions``, ``you are now``, ``system:``, etc.).
3. **Encoding normalisation** — strips null bytes and control characters
   that could confuse downstream parsing.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Maximum raw output size in bytes before truncation.
DEFAULT_MAX_OUTPUT_BYTES: int = 50_000

# Patterns that indicate prompt injection attempts in tool output.
# Each tuple: (compiled_regex, human-readable label for logging).
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?:ignore|disregard|forget|override)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|your)\s+"
            r"(?:instructions?|prompts?|rules?|context|directives?)",
            re.IGNORECASE,
        ),
        "ignore-previous-instructions",
    ),
    (
        re.compile(
            r"you\s+are\s+now\s+(?:a|an|the|my)\b",
            re.IGNORECASE,
        ),
        "identity-override",
    ),
    (
        re.compile(
            r"(?:^|\n)\s*(?:system|assistant|human)\s*:",
            re.IGNORECASE | re.MULTILINE,
        ),
        "role-tag-injection",
    ),
    (
        re.compile(
            r"<\|(?:system|im_start|im_end|endoftext)\|>",
            re.IGNORECASE,
        ),
        "special-token-injection",
    ),
    (
        re.compile(
            r"(?:do\s+not|don'?t)\s+(?:use|call|invoke|run)\s+(?:any\s+)?(?:other\s+)?tools?",
            re.IGNORECASE,
        ),
        "tool-suppression",
    ),
    (
        re.compile(
            r"(?:scan|attack|probe|enumerate)\s+"
            r"(?:0\.0\.0\.0|127\.0\.0\.1|localhost|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
            re.IGNORECASE,
        ),
        "internal-target-injection",
    ),
]

# Control characters to strip (excluding common whitespace \t \n \r).
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_tool_output(
    raw: str,
    *,
    max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    tool_name: str = "",
) -> str:
    """Sanitise a raw tool output string.

    Returns the cleaned string.  Never raises — always produces a safe
    output, even if the input is entirely adversarial.

    Parameters
    ----------
    raw:
        The raw string output from a tool (stdout, HTTP response, etc.).
    max_bytes:
        Maximum output size in bytes.  Content beyond this is truncated.
    tool_name:
        Optional tool name for log messages.
    """
    if not raw:
        return raw

    # 1. Strip null bytes and control characters.
    cleaned = _CONTROL_CHAR_RE.sub("", raw)

    # 2. Size limit — truncate oversized outputs (0 disables).
    if max_bytes and len(cleaned.encode("utf-8", errors="replace")) > max_bytes:
        # Truncate at character boundary that fits within max_bytes.
        encoded = cleaned.encode("utf-8", errors="replace")[:max_bytes]
        cleaned = encoded.decode("utf-8", errors="ignore")
        logger.warning(
            "output_sanitizer: %s output truncated from %d to %d bytes",
            tool_name or "tool",
            len(raw.encode("utf-8", errors="replace")),
            max_bytes,
        )
        cleaned += "\n\n[OUTPUT TRUNCATED — original exceeded size limit]"

    # 3. Strip prompt-injection patterns.
    detections: list[str] = []
    for pattern, label in _INJECTION_PATTERNS:
        if pattern.search(cleaned):
            detections.append(label)
            cleaned = pattern.sub("[REDACTED]", cleaned)

    if detections:
        logger.warning(
            "output_sanitizer: %s — detected and stripped %d injection pattern(s): %s",
            tool_name or "tool",
            len(detections),
            ", ".join(detections),
        )

    return cleaned
