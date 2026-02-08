from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from fackel.core.store import StructuredStore


class AgentState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore", frozen=False)

    domain: str
    active_scan: bool = False
    plan: list[str] = Field(default_factory=list)
    completed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    last_result: str | None = None
    store: StructuredStore
