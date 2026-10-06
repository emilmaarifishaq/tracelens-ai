"""Data models for machine learning components."""

from typing import Any
from pydantic import BaseModel, Field


class TimeSeriesModel(BaseModel):
    """Trained time-series forecasting model."""

    model_id: str
    metric_name: str
    model_type: str  # "exponential_smoothing", "arima", "simple_trend"
    alpha: float | None = None  # Smoothing parameter for exponential smoothing
    trend_slope: float | None = None  # Trend slope for linear models
    baseline_mean: float | None = None  # Mean for normalization
    baseline_std: float | None = None  # Std dev for normalization
    training_samples: int
    model_accuracy: float  # 0-1 (R² or similar)
    last_training: str  # ISO timestamp
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnomalyThresholds(BaseModel):
    """Learned anomaly detection thresholds."""

    metric_name: str
    z_score_threshold: float  # Dynamic z-score threshold (typically 2.0-3.0)
    iqr_multiplier: float  # Dynamic IQR multiplier (typically 1.5)
    baseline_mean: float
    baseline_std: float
    percentile_95: float  # 95th percentile for one-sided detection
    percentile_5: float  # 5th percentile for one-sided detection
    confidence: float  # 0-1, confidence in thresholds
    training_window_hours: int
    samples_used: int
    last_updated: str  # ISO timestamp


class ClusteringResult(BaseModel):
    """Root cause clustering result."""

    cluster_id: str
    cluster_name: str  # Descriptive name (e.g., "Radio Issues", "Network Congestion")
    cause_codes: list[str]  # Cause codes in this cluster
    occurrence_count: int
    percentage_of_total: float
    common_symptoms: list[str]  # Associated findings
    recommended_resolution: str
    cluster_confidence: float  # 0-1
    created_at: str


class ClusteringAnalysis(BaseModel):
    """Complete clustering analysis."""

    analysis_id: str
    metric_period_hours: int
    total_failures: int
    clusters: list[ClusteringResult] = Field(default_factory=list)
    cluster_count: int
    silhouette_score: float | None = None  # Clustering quality metric
    dominant_cluster: str | None = None  # Largest cluster ID
    timestamp: str  # ISO timestamp


class ModelMetrics(BaseModel):
    """Model performance metrics."""

    model_id: str
    metric_name: str
    model_type: str
    accuracy: float  # 0-1 (R² for regression)
    mae: float  # Mean Absolute Error
    rmse: float  # Root Mean Squared Error
    mape: float | None = None  # Mean Absolute Percentage Error
    prediction_horizon: int  # Hours ahead
    test_set_size: int
    evaluation_timestamp: str  # ISO timestamp


class SeasonalDecomposition(BaseModel):
    """Time-series seasonal decomposition."""

    metric_name: str
    period_hours: int  # Seasonality period (24 for daily, 168 for weekly)
    trend: list[float]  # Trend component
    seasonal: list[float]  # Seasonal component
    residual: list[float]  # Residual/noise component
    variance_explained: float  # 0-1, proportion of variance explained by trend+seasonal
    trend_direction: str  # "improving", "degrading", "stable"
    seasonal_strength: float  # 0-1, strength of seasonality
    decomposition_quality: float  # 0-1, fit quality
    timestamp: str


class ForecastingResult(BaseModel):
    """Time-series forecasting result."""

    forecast_id: str
    metric_name: str
    model_type: str
    current_value: float
    forecast_horizon: int  # Hours ahead
    point_forecast: list[float]  # Single point forecasts
    lower_bound: list[float]  # Confidence interval lower
    upper_bound: list[float]  # Confidence interval upper
    confidence_level: float  # 0.9, 0.95, 0.99
    forecast_accuracy_estimate: float  # 0-1
    timestamps: list[str]  # ISO timestamps for each forecast point
    model_id: str | None = None
    warning_flags: list[str] = Field(default_factory=list)  # e.g., "crossing_threshold"
    generated_at: str


class PatternDetectionResult(BaseModel):
    """Detected patterns in historical data."""

    pattern_id: str
    metric_name: str
    pattern_type: str  # "cyclic", "trend", "burst", "plateau"
    confidence: float  # 0-1
    description: str
    start_time: str  # ISO timestamp
    end_time: str  # ISO timestamp
    impact: float  # 0-1, impact on KPIs
    frequency: str  # "daily", "weekly", "monthly", "one_time"
    recommended_action: str
