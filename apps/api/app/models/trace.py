from pydantic import BaseModel, Field


class DecodedTrace(BaseModel):
    trace_id: str
    events: list[dict] = Field(default_factory=list)


class TraceAnalysis(BaseModel):
    errors: list[dict] = Field(default_factory=list)
    ai_context: dict = Field(default_factory=dict)

