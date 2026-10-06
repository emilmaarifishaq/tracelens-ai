"""Data models for dashboard and visualization components."""

from typing import Any

from pydantic import BaseModel, Field


class ChartDataPoint(BaseModel):
    """Single data point for a chart."""

    timestamp: str  # ISO format
    value: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChartData(BaseModel):
    """Chart data for visualization."""

    chart_id: str
    chart_type: str  # "line", "area", "bar", "gauge", "sparkline"
    title: str
    description: str | None = None
    metric_name: str | None = None
    unit: str | None = None
    data_points: list[ChartDataPoint] = Field(default_factory=list)
    min_value: float | None = None
    max_value: float | None = None
    current_value: float | None = None
    trend_direction: str | None = None  # "improving", "degrading", "stable"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnomalyMarker(BaseModel):
    """Marker for anomalies on a chart."""

    timestamp: str
    value: float
    severity: str  # "high", "medium", "low"
    description: str
    z_score: float | None = None


class ForecastBand(BaseModel):
    """Forecast confidence band for projections."""

    start_timestamp: str
    end_timestamp: str
    lower_bound: float
    upper_bound: float
    expected_value: float
    probability: float
    label: str | None = None


class KPICard(BaseModel):
    """KPI summary card for dashboard."""

    metric_name: str
    current_value: float
    previous_value: float | None = None
    unit: str | None = None
    trend: str | None = None  # "improving", "degrading", "stable"
    change_percentage: float = 0.0
    status: str  # "healthy", "warning", "critical"
    sparkline_data: list[float] = Field(default_factory=list)
    alert_message: str | None = None


class DashboardLayout(BaseModel):
    """Dashboard layout configuration."""

    dashboard_id: str
    name: str
    description: str | None = None
    sections: list[str] = Field(default_factory=list)  # Section IDs
    refresh_interval_seconds: int = 60
    metadata: dict[str, Any] = Field(default_factory=dict)


class DashboardSection(BaseModel):
    """Section within a dashboard."""

    section_id: str
    name: str
    section_type: str  # "kpi_grid", "charts", "alerts", "timeline"
    rows: int = 1
    columns: int = 1
    widgets: list[str] = Field(default_factory=list)  # Widget IDs
    metadata: dict[str, Any] = Field(default_factory=dict)


class DashboardWidget(BaseModel):
    """Individual dashboard widget."""

    widget_id: str
    widget_type: str  # "chart", "kpi_card", "alert_list", "forecast"
    title: str
    row: int
    column: int
    width: int = 1  # Grid width
    height: int = 1  # Grid height
    chart_data: ChartData | None = None
    kpi_card: KPICard | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertTimeline(BaseModel):
    """Timeline of alerts and rule violations."""

    alert_id: str
    timestamp: str
    alert_type: str  # "finding", "anomaly", "forecast", "rule_violation"
    severity: str  # "critical", "warning", "info"
    title: str
    description: str
    source: str  # "finding_detector", "anomaly_detector", etc.
    metadata: dict[str, Any] = Field(default_factory=dict)


class ComparisonMetric(BaseModel):
    """Metric comparison (current vs historical)."""

    metric_name: str
    current: float
    previous: float
    change: float
    change_percentage: float
    time_period: str  # "1h", "24h", "7d", "30d"
    status: str  # "improved", "degraded", "stable"


class CorrelationPair(BaseModel):
    """Correlation between two metrics."""

    metric_a: str
    metric_b: str
    correlation_coefficient: float  # -1 to 1
    strength: str  # "strong", "moderate", "weak"
    sample_size: int
    description: str | None = None


class HealthScore(BaseModel):
    """Overall network health score."""

    score: float  # 0-100
    status: str  # "healthy", "degraded", "critical"
    components: dict[str, float]  # Component scores
    last_update: str  # ISO timestamp
    factors: list[str] = Field(default_factory=list)  # Contributing factors
