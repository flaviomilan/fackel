from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from fackel.core.store import StructuredStore


class AgentState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore", frozen=False)

    domain: str
    active_scan: bool = False
    plan: List[str] = Field(default_factory=list)
    completed: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    confidence: float = 0.5
    last_result: Optional[str] = None
    store: StructuredStore
