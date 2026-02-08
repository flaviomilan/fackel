from __future__ import annotations

import os
from dataclasses import dataclass

from collectors.collectors import get_tool_registry


@dataclass
class Capabilities:
    available: set[str]
    missing: dict[str, list[str]]

    def summary_lines(self) -> list[str]:
        lines = []
        if self.available:
            lines.append(
                "Ferramentas habilitadas: " + ", ".join(sorted(self.available))
            )
        if self.missing:
            details = [
                f"{tool} (faltam: {', '.join(vars)})"
                for tool, vars in self.missing.items()
            ]
            lines.append("Ferramentas desabilitadas: " + "; ".join(sorted(details)))
        return lines


def detect_capabilities() -> Capabilities:
    available: set[str] = set()
    missing: dict[str, list[str]] = {}

    registry = get_tool_registry()
    requirements = registry.get_requirements()

    for tool_name, required_vars in requirements.items():
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            missing[tool_name] = missing_vars
        else:
            available.add(tool_name)

    return Capabilities(available=available, missing=missing)
