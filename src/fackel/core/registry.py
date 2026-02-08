from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal

ToolCategory = Literal["passive", "active"]
ToolFn = Callable[[Any], Any]


@dataclass(slots=True)
class ToolDefinition:
    name: str
    fn: ToolFn
    category: ToolCategory = "passive"
    required_env: list[str] = None

    def __post_init__(self):
        if self.required_env is None:
            object.__setattr__(self, "required_env", [])


class ToolRegistry:
    """Registry that allows extending tools at runtime (free/pro/plugins)."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._by_category: dict[ToolCategory, set[str]] = {
            "passive": set(),
            "active": set(),
        }

    def register(
        self,
        name: str,
        fn: ToolFn,
        category: ToolCategory = "passive",
        required_env: list[str] = None,
    ) -> None:
        self._tools[name] = ToolDefinition(
            name=name, fn=fn, category=category, required_env=required_env or []
        )
        self._by_category.setdefault(category, set()).add(name)

    def get_requirements(self) -> dict[str, list[str]]:
        """Return a mapping of tool name to required env vars."""
        return {name: td.required_env for name, td in self._tools.items()}

    def get(self, name: str) -> ToolFn | None:
        definition = self._tools.get(name)
        return definition.fn if definition else None

    def names(self, category: ToolCategory | None = None) -> list[str]:
        if category is None:
            return list(self._tools.keys())
        return list(self._by_category.get(category, set()))

    def plan(self, available: set[str], active_scan: bool) -> list[str]:
        """Compute the ordered plan given capabilities and mode."""
        passives = [name for name in self.names("passive") if name in available]
        actives = (
            [name for name in self.names("active") if name in available]
            if active_scan
            else []
        )
        return passives + actives
