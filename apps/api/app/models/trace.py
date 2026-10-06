from typing import Any

from pydantic import BaseModel, Field

from app.models.ue_context import UEContext


class DecodedTrace(BaseModel):
    trace_id: str
    events: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    ue_contexts: list[UEContext] = Field(default_factory=list)


class KPIMetrics(BaseModel):
    """Key Performance Indicators calculated from UE contexts."""

    total_ues: int = 0
    complete_ues: int = 0
    completion_rate: float = 0.0
    registration_success_rate: float = 0.0
    ics_success_rate: float = 0.0
    pdu_session_success_rate: float = 0.0
    procedure_timing: dict[str, Any] = Field(default_factory=dict)
    drop_rate_by_cause: dict[str, float] = Field(default_factory=dict)
    success_rate_by_cause: dict[str, float] = Field(default_factory=dict)
    event_counts: dict[str, int] = Field(default_factory=dict)
    failure_rate_by_type: dict[str, float] = Field(default_factory=dict)


class FindingModel(BaseModel):
    """Detected finding or anomaly in trace."""

    finding_type: str
    severity: str
    title: str
    description: str
    affected_ues: int = 0
    metric_value: float = 0.0
    cause_class: str | None = None
    procedure: str | None = None
    score: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class InsightModel(BaseModel):
    """AI-generated insight or recommendation from analysis."""

    insight_type: str
    priority: str
    title: str
    description: str
    root_cause: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    affected_kpis: list[str] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    impact_score: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class TraceAnalysis(BaseModel):
    errors: list[dict] = Field(default_factory=list)
    ai_context: dict = Field(default_factory=dict)
    kpi_metrics: KPIMetrics | None = None
    findings: list[FindingModel] = Field(default_factory=list)
    insights: list[InsightModel] = Field(default_factory=list)
