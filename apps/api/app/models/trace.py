from pydantic import BaseModel, Field

from app.models.ue_context import UEContext


class DecodedTrace(BaseModel):
    trace_id: str
    events: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    ue_contexts: list[UEContext] = Field(default_factory=list)


class TraceAnalysis(BaseModel):
    errors: list[dict] = Field(default_factory=list)
    ai_context: dict = Field(default_factory=dict)

