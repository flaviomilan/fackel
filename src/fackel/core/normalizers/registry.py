from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..store import StructuredStore

NormalizerFn = Callable[[str, Any, StructuredStore], None]


class NormalizerRegistry:
    def __init__(self):
        self._registry: dict[str, NormalizerFn] = {}

    def register(self, tool_name: str, fn: NormalizerFn) -> None:
        self._registry[tool_name] = fn

    def normalize(self, tool: str, output: Any, store: StructuredStore) -> None:
        fn = self._registry.get(tool)
        if fn:
            fn(tool, output, store)
