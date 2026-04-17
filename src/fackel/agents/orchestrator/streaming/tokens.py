"""Token estimation for context trimming and the live context meter."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from fackel.settings import get_settings


def _estimate_tokens(messages: list[Any]) -> int:
    """Token estimate using ``tiktoken`` when available.

    Uses the configured chat model's encoder if it is recognised by
    ``tiktoken``; falls back to a conservative heuristic
    (``len(text) / 3``) for non-OpenAI models or when ``tiktoken`` is
    unavailable.  Result is used by :func:`langchain_core.messages.trim_messages`
    as a guard-rail; the model's own tokenizer handles exact counting at
    inference time.
    """
    encoder = _get_encoder()
    total = 0
    for msg in messages:
        content = getattr(msg, "content", "")
        if isinstance(content, str):
            total += _count(content, encoder)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, str):
                    total += _count(block, encoder)
                elif isinstance(block, dict):
                    total += _count(str(block.get("text", "")), encoder)
    return total


def _count(text: str, encoder: Any) -> int:
    """Count tokens in *text* using *encoder* or the heuristic fallback."""
    if encoder is not None:
        try:
            return len(encoder.encode(text))
        except Exception:  # noqa: S110 - fall through to heuristic
            pass
    # Conservative fallback: ~3 chars/token (overestimates slightly so
    # we never exceed the real context window).
    return len(text) // 3 + 1


def text_tokens(text: str) -> int:
    """Estimate the token count of *text* using the configured model's encoder.

    Public helper for the CLI context meter — shares the same encoder/heuristic
    as :func:`_estimate_tokens` so live counts are consistent with trimming."""
    if not text:
        return 0
    return _count(text, _get_encoder())


@lru_cache(maxsize=4)
def _get_encoder_for_model(model_name: str) -> Any:
    """Return the ``tiktoken`` encoder for *model_name* or ``None``."""
    try:
        import tiktoken
    except ImportError:  # pragma: no cover - tiktoken comes with openai
        return None
    try:
        return tiktoken.encoding_for_model(model_name)
    except Exception:
        try:
            return tiktoken.get_encoding("cl100k_base")
        except Exception:  # pragma: no cover
            return None


def _get_encoder() -> Any:
    """Return the tiktoken encoder for the currently configured model."""
    model = getattr(get_settings(), "default_model", None) or "gpt-4o-mini"
    return _get_encoder_for_model(model)
