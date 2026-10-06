"""Data models for advanced analytics features."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HistoricalMetric(BaseModel):
    """Historical KPI metric snapshot at a point in time."""

    timestamp: datetime
    trace_id: str
    registration_success_rate: float = 0.0
    ics_success_rate: float = 0.0
    pdu_session_success_rate: float = 0.0
    completion_rate: float = 0.0
    avg_registration_time: float = 0.0
    avg_ics_time: float = 0.0
    avg_pdu_session_time: float = 0.0
    total_ues: int = 0
    complete_ues: int = 0
    high_drop_rate_findings: int = 0
    high_latency_findings: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricTrend(BaseModel):
    """Trend analysis for a metric over time."""

    metric_name: str
    current_value: float
    previous_value: float | None = None
    trend_direction: str  # "improving", "degrading", "stable"
    trend_confidence: float = 0.0  # 0-1
    change_percentage: float = 0.0  # % change
    data_points: int = 0
    time_period_hours: float = 0.0


class AnomalyScore(BaseModel):
    """Anomaly detection score for a metric."""

    metric_name: str
    metric_value: float
    expected_value: float
    z_score: float  # Statistical z-score
    is_anomaly: bool
    severity: str  # "high", "medium", "low", "none"
    confidence: float = 0.0  # 0-1
    details: dict[str, Any] = Field(default_factory=dict)


class PredictiveInsight(BaseModel):
    """Predictive insight about future state."""

    insight_type: str
    predicted_issue: str
    probability: float = 0.0  # 0-1 likelihood
    time_horizon_hours: int = 0
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: float = 0.0  # 0-1
    details: dict[str, Any] = Field(default_factory=dict)


class CustomRule(BaseModel):
    """User-defined custom rule for trace analysis."""

    rule_id: str
    name: str
    description: str | None = None
    rule_type: str  # "threshold", "trend", "anomaly", "composite"
    metric_name: str | None = None
    operator: str | None = None  # ">", "<", "==", "between", "trend_change"
    threshold: float | None = None
    threshold_high: float | None = None  # For "between"
    enabled: bool = True
    severity: str = "info"  # "critical", "warning", "info"
    recommended_actions: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_modified: datetime = Field(default_factory=datetime.utcnow)


class CustomRuleResult(BaseModel):
    """Result of evaluating a custom rule."""

    rule_id: str
    rule_name: str
    triggered: bool
    severity: str
    matched_value: float | None = None
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
