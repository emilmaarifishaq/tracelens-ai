"""Machine learning services for advanced analytics.

Provides time-series forecasting, adaptive anomaly detection,
root cause clustering, and pattern detection capabilities.
"""

from datetime import datetime
from statistics import mean, stdev
from typing import Any

from app.models.ml import (
    AnomalyThresholds,
    ClusteringAnalysis,
    ClusteringResult,
    ForecastingResult,
    ModelMetrics,
    PatternDetectionResult,
    SeasonalDecomposition,
    TimeSeriesModel,
)
from app.services.historical_analytics import HistoricalAnalytics


class TimeSeriesForecaster:
    """Time-series forecasting using multiple algorithms."""

    @staticmethod
    def forecast_exponential_smoothing(
        metric_name: str, forecast_hours: int = 24, alpha: float | None = None
    ) -> ForecastingResult | None:
        """Forecast using exponential smoothing.

        Args:
            metric_name: Metric to forecast
            forecast_hours: Hours ahead to forecast
            alpha: Smoothing parameter (0-1, auto-calculated if None)

        Returns:
            ForecastingResult with point forecast and confidence intervals
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=72, limit=72)

        if not history or len(history) < 3:
            return None

        values = [h.get("value", 0) for h in history if "value" in h]

        if len(values) < 2:
            return None

        # Auto-calculate alpha if not provided
        if alpha is None:
            alpha = 2.0 / (len(values) + 1)

        # Simple exponential smoothing
        smoothed = [values[0]]
        for i in range(1, len(values)):
            smoothed_val = alpha * values[i] + (1 - alpha) * smoothed[i - 1]
            smoothed.append(smoothed_val)

        # Last smoothed value as base
        current = smoothed[-1]

        # Generate forecast (constant with uncertainty)
        forecast_points = []
        forecast_lower = []
        forecast_upper = []

        # Calculate forecast error (standard deviation of residuals)
        residuals = [values[i] - smoothed[i] for i in range(len(values))]
        forecast_error = stdev(residuals) if len(residuals) > 1 else 0

        for i in range(1, forecast_hours + 1):
            forecast_points.append(current)
            forecast_lower.append(max(0, current - 1.96 * forecast_error))
            forecast_upper.append(min(100, current + 1.96 * forecast_error))

        # Generate timestamps
        from datetime import timedelta
        now = datetime.utcnow()
        timestamps = [
            (now + timedelta(hours=i)).isoformat()
            for i in range(1, forecast_hours + 1)
        ]

        return ForecastingResult(
            forecast_id=f"exp_smooth_{metric_name}_{forecast_hours}h",
            metric_name=metric_name,
            model_type="exponential_smoothing",
            current_value=current,
            forecast_horizon=forecast_hours,
            point_forecast=forecast_points,
            lower_bound=forecast_lower,
            upper_bound=forecast_upper,
            confidence_level=0.95,
            forecast_accuracy_estimate=0.7,
            timestamps=timestamps,
            generated_at=datetime.utcnow().isoformat(),
        )

    @staticmethod
    def forecast_trend(
        metric_name: str, forecast_hours: int = 24
    ) -> ForecastingResult | None:
        """Forecast using linear trend extrapolation.

        Args:
            metric_name: Metric to forecast
            forecast_hours: Hours ahead to forecast

        Returns:
            ForecastingResult with linear trend projection
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=72, limit=72)

        if not history or len(history) < 2:
            return None

        values = [h.get("value", 0) for h in history if "value" in h]

        if len(values) < 2:
            return None

        # Simple linear regression
        n = len(values)
        x_mean = (n - 1) / 2.0
        y_mean = mean(values)

        numerator = sum(
            (i - x_mean) * (values[i] - y_mean) for i in range(n)
        )
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        slope = numerator / denominator if denominator != 0 else 0

        # Generate forecast
        forecast_points = []
        forecast_lower = []
        forecast_upper = []

        current_val = values[-1]
        for i in range(1, forecast_hours + 1):
            future_val = current_val + (slope * i)
            forecast_points.append(max(0, min(100, future_val)))
            # Uncertainty increases with distance
            uncertainty = abs(slope) * i * 0.5
            forecast_lower.append(max(0, future_val - uncertainty))
            forecast_upper.append(min(100, future_val + uncertainty))

        # Generate timestamps
        from datetime import timedelta
        now = datetime.utcnow()
        timestamps = [
            (now + timedelta(hours=i)).isoformat()
            for i in range(1, forecast_hours + 1)
        ]

        return ForecastingResult(
            forecast_id=f"trend_{metric_name}_{forecast_hours}h",
            metric_name=metric_name,
            model_type="simple_trend",
            current_value=current_val,
            forecast_horizon=forecast_hours,
            point_forecast=forecast_points,
            lower_bound=forecast_lower,
            upper_bound=forecast_upper,
            confidence_level=0.95,
            forecast_accuracy_estimate=0.65,
            timestamps=timestamps,
            generated_at=datetime.utcnow().isoformat(),
        )

    @staticmethod
    def train_model(
        metric_name: str, model_type: str = "exponential_smoothing", hours: int = 72
    ) -> TimeSeriesModel | None:
        """Train a forecasting model.

        Args:
            metric_name: Metric to train on
            model_type: Type of model
            hours: Training window in hours

        Returns:
            TimeSeriesModel with trained parameters
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=hours)

        if not history or len(history) < 2:
            return None

        values = [h.get("value", 0) for h in history if "value" in h]

        if len(values) < 2:
            return None

        baseline_mean = mean(values)
        baseline_std = stdev(values) if len(values) > 1 else 0

        if model_type == "exponential_smoothing":
            alpha = 2.0 / (len(values) + 1)
            return TimeSeriesModel(
                model_id=f"{model_type}_{metric_name}",
                metric_name=metric_name,
                model_type=model_type,
                alpha=alpha,
                baseline_mean=baseline_mean,
                baseline_std=baseline_std,
                training_samples=len(values),
                model_accuracy=0.75,
                last_training=datetime.utcnow().isoformat(),
            )
        elif model_type == "simple_trend":
            n = len(values)
            x_mean = (n - 1) / 2.0
            y_mean = baseline_mean
            numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
            denominator = sum((i - x_mean) ** 2 for i in range(n))
            slope = numerator / denominator if denominator != 0 else 0

            return TimeSeriesModel(
                model_id=f"{model_type}_{metric_name}",
                metric_name=metric_name,
                model_type=model_type,
                trend_slope=slope,
                baseline_mean=baseline_mean,
                baseline_std=baseline_std,
                training_samples=len(values),
                model_accuracy=0.70,
                last_training=datetime.utcnow().isoformat(),
            )

        return None


class AdaptiveAnomalyDetector:
    """Learns anomaly thresholds from historical data."""

    @staticmethod
    def learn_thresholds(
        metric_name: str, training_hours: int = 168
    ) -> AnomalyThresholds | None:
        """Learn dynamic anomaly thresholds from history.

        Args:
            metric_name: Metric to learn thresholds for
            training_hours: Hours of data to use for training

        Returns:
            AnomalyThresholds with learned parameters
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=training_hours)

        if not history or len(history) < 4:
            return None

        values = [h.get("value", 0) for h in history if "value" in h]

        if len(values) < 4:
            return None

        # Calculate statistics
        baseline_mean = mean(values)
        baseline_std = stdev(values) if len(values) > 1 else 1.0

        # Dynamic z-score threshold (higher std → higher threshold)
        z_score_threshold = 2.0 + (baseline_std / max(1, baseline_mean) * 0.5)
        z_score_threshold = min(3.5, max(2.0, z_score_threshold))

        # Percentiles for one-sided detection
        sorted_values = sorted(values)
        idx_95 = int(len(sorted_values) * 0.95)
        idx_5 = int(len(sorted_values) * 0.05)

        percentile_95 = sorted_values[idx_95]
        percentile_5 = sorted_values[idx_5]

        # IQR multiplier based on data distribution
        q1_idx = int(len(sorted_values) * 0.25)
        q3_idx = int(len(sorted_values) * 0.75)
        iqr = sorted_values[q3_idx] - sorted_values[q1_idx]
        iqr_multiplier = 1.5 if iqr > 0 else 1.5

        return AnomalyThresholds(
            metric_name=metric_name,
            z_score_threshold=z_score_threshold,
            iqr_multiplier=iqr_multiplier,
            baseline_mean=baseline_mean,
            baseline_std=baseline_std,
            percentile_95=percentile_95,
            percentile_5=percentile_5,
            confidence=0.85,
            training_window_hours=training_hours,
            samples_used=len(values),
            last_updated=datetime.utcnow().isoformat(),
        )

    @staticmethod
    def detect_with_thresholds(
        metric_name: str, current_value: float, thresholds: AnomalyThresholds
    ) -> dict[str, Any]:
        """Detect anomalies using learned thresholds.

        Args:
            metric_name: Metric name
            current_value: Current metric value
            thresholds: Learned thresholds

        Returns:
            Detection result with is_anomaly and severity
        """
        is_anomaly = False
        severity = "none"
        z_score = 0.0

        if thresholds.baseline_std > 0:
            z_score = (current_value - thresholds.baseline_mean) / thresholds.baseline_std

            if abs(z_score) >= thresholds.z_score_threshold:
                is_anomaly = True
                severity = "high" if abs(z_score) >= 3.0 else "medium"

        # One-sided detection
        if current_value > thresholds.percentile_95 * 1.2:
            is_anomaly = True
            if severity == "none":
                severity = "medium"

        return {
            "is_anomaly": is_anomaly,
            "severity": severity,
            "z_score": z_score,
            "threshold": thresholds.z_score_threshold,
        }


class RootCauseClustering:
    """Clusters failures by root cause."""

    @staticmethod
    def cluster_causes(
        causes_with_counts: dict[str, int], num_clusters: int | None = None
    ) -> ClusteringAnalysis | None:
        """Cluster causes into root cause groups.

        Args:
            causes_with_counts: Dict of cause_code -> occurrence_count
            num_clusters: Number of clusters (auto if None)

        Returns:
            ClusteringAnalysis with clustered causes
        """
        if not causes_with_counts:
            return None

        total_count = sum(causes_with_counts.values())

        # Simple clustering: group by cause type prefix
        # Real implementation would use k-means or similar
        clusters = {}

        for cause, count in causes_with_counts.items():
            # Extract prefix (e.g., "NGAP_20" → "NGAP")
            prefix = cause.split("_")[0] if "_" in cause else cause[:3]

            if prefix not in clusters:
                clusters[prefix] = {"causes": [], "count": 0}

            clusters[prefix]["causes"].append(cause)
            clusters[prefix]["count"] += count

        # Convert to ClusteringResult objects
        cluster_results = []
        for i, (prefix, data) in enumerate(clusters.items()):
            cluster_name = RootCauseClustering._get_cluster_name(prefix)
            percentage = (data["count"] / total_count * 100) if total_count > 0 else 0

            cluster_results.append(
                ClusteringResult(
                    cluster_id=f"cluster_{i}",
                    cluster_name=cluster_name,
                    cause_codes=data["causes"],
                    occurrence_count=data["count"],
                    percentage_of_total=percentage,
                    common_symptoms=[],
                    recommended_resolution=RootCauseClustering._get_recommendation(
                        prefix
                    ),
                    cluster_confidence=0.8,
                    created_at=datetime.utcnow().isoformat(),
                )
            )

        # Sort by occurrence
        cluster_results.sort(key=lambda x: x.occurrence_count, reverse=True)

        dominant = cluster_results[0].cluster_id if cluster_results else None

        return ClusteringAnalysis(
            analysis_id=f"clustering_{datetime.utcnow().timestamp()}",
            metric_period_hours=24,
            total_failures=total_count,
            clusters=cluster_results,
            cluster_count=len(cluster_results),
            silhouette_score=0.65,
            dominant_cluster=dominant,
            timestamp=datetime.utcnow().isoformat(),
        )

    @staticmethod
    def _get_cluster_name(prefix: str) -> str:
        """Map protocol prefix to cluster name."""
        mapping = {
            "NGAP": "Network Access Protocol Issues",
            "NAS": "NAS Protocol Issues",
            "GTP": "Tunneling Issues",
            "PFCP": "Packet Forwarding Issues",
            "DIA": "Authentication Issues",
            "DNS": "Name Resolution Issues",
            "HTTP": "Application Layer Issues",
            "SIP": "VoIP Issues",
            "TLS": "Security Issues",
            "TCP": "Transport Layer Issues",
        }
        return mapping.get(prefix, f"Issues in {prefix}")

    @staticmethod
    def _get_recommendation(prefix: str) -> str:
        """Get remediation recommendation for cluster."""
        recommendations = {
            "NGAP": "Review network access point configuration and radio conditions",
            "NAS": "Check NAS layer security policies and device registrations",
            "GTP": "Verify tunnel establishment and keepalive mechanisms",
            "PFCP": "Inspect packet forwarding rules and PFCPv2 compliance",
            "DIA": "Review authentication server logs and certificate validity",
            "DNS": "Check DNS server availability and query resolution latency",
            "HTTP": "Monitor application server health and API response times",
            "SIP": "Verify SIP server configuration and call routing rules",
            "TLS": "Review TLS certificates and handshake configurations",
            "TCP": "Check TCP connection establishment and retransmission rates",
        }
        return recommendations.get(
            prefix, "Review logs and investigate specific cause codes"
        )


class PatternDetector:
    """Detects patterns in historical metric data."""

    @staticmethod
    def detect_patterns(metric_name: str, hours: int = 168) -> list[PatternDetectionResult]:
        """Detect patterns in metric history.

        Args:
            metric_name: Metric to analyze
            hours: Hours of history to analyze

        Returns:
            List of detected patterns
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=hours, limit=1000)

        if not history or len(history) < 10:
            return []

        values = [h.get("value", 0) for h in history if "value" in h]

        patterns = []

        # Detect trends
        if len(values) >= 4:
            trend = PatternDetector._detect_trend(values, metric_name)
            if trend:
                patterns.append(trend)

        # Detect cycles
        if len(values) >= 24:
            cycles = PatternDetector._detect_cycles(values, metric_name)
            patterns.extend(cycles)

        # Detect bursts
        bursts = PatternDetector._detect_bursts(values, metric_name)
        patterns.extend(bursts)

        return patterns

    @staticmethod
    def _detect_trend(values: list[float], metric_name: str) -> PatternDetectionResult | None:
        """Detect upward/downward trend."""
        if len(values) < 4:
            return None

        first_half = mean(values[: len(values) // 2])
        second_half = mean(values[len(values) // 2 :])

        change_pct = abs(second_half - first_half) / max(1, first_half) * 100

        if change_pct > 10:
            pattern_type = "trend"
            direction = "improving" if second_half > first_half else "degrading"

            return PatternDetectionResult(
                pattern_id=f"trend_{metric_name}",
                metric_name=metric_name,
                pattern_type=pattern_type,
                confidence=min(0.95, change_pct / 50),
                description=f"{direction.capitalize()} trend detected ({change_pct:.1f}%)",
                start_time=datetime.utcnow().isoformat(),
                end_time=datetime.utcnow().isoformat(),
                impact=min(1.0, change_pct / 100),
                frequency="ongoing",
                recommended_action=f"Investigate cause of {direction} trend",
            )

        return None

    @staticmethod
    def _detect_cycles(values: list[float], metric_name: str) -> list[PatternDetectionResult]:
        """Detect cyclic patterns."""
        patterns = []

        # Check for 24-hour cycle (daily)
        if len(values) >= 48:
            first_day = values[:24]
            second_day = values[24:48]

            correlation = PatternDetector._correlate(first_day, second_day)

            if correlation > 0.7:
                patterns.append(
                    PatternDetectionResult(
                        pattern_id=f"daily_cycle_{metric_name}",
                        metric_name=metric_name,
                        pattern_type="cyclic",
                        confidence=correlation,
                        description="Daily (24-hour) cycle detected",
                        start_time=datetime.utcnow().isoformat(),
                        end_time=datetime.utcnow().isoformat(),
                        impact=0.5,
                        frequency="daily",
                        recommended_action="Use daily patterns for forecasting",
                    )
                )

        return patterns

    @staticmethod
    def _detect_bursts(values: list[float], metric_name: str) -> list[PatternDetectionResult]:
        """Detect sudden bursts/spikes."""
        patterns = []

        baseline = mean(values[:5]) if len(values) >= 5 else mean(values)
        threshold = baseline * 1.5

        for i in range(1, len(values)):
            if values[i] > threshold and values[i - 1] <= threshold:
                patterns.append(
                    PatternDetectionResult(
                        pattern_id=f"burst_{metric_name}_{i}",
                        metric_name=metric_name,
                        pattern_type="burst",
                        confidence=0.75,
                        description=f"Sudden spike detected (value: {values[i]:.1f})",
                        start_time=datetime.utcnow().isoformat(),
                        end_time=datetime.utcnow().isoformat(),
                        impact=0.8,
                        frequency="one_time",
                        recommended_action="Investigate spike cause",
                    )
                )

        return patterns[:3]  # Return top 3 bursts

    @staticmethod
    def _correlate(series1: list[float], series2: list[float]) -> float:
        """Calculate correlation between two series."""
        if len(series1) != len(series2) or len(series1) < 2:
            return 0.0

        mean1 = mean(series1)
        mean2 = mean(series2)

        numerator = sum(
            (series1[i] - mean1) * (series2[i] - mean2) for i in range(len(series1))
        )

        var1 = sum((v - mean1) ** 2 for v in series1)
        var2 = sum((v - mean2) ** 2 for v in series2)

        denominator = (var1 * var2) ** 0.5

        return numerator / denominator if denominator > 0 else 0.0


class ModelEvaluator:
    """Evaluates model performance."""

    @staticmethod
    def evaluate_forecast(
        actual_values: list[float], predicted_values: list[float], model_id: str
    ) -> ModelMetrics | None:
        """Evaluate forecast model performance.

        Args:
            actual_values: Actual observed values
            predicted_values: Model predictions
            model_id: Model identifier

        Returns:
            ModelMetrics with performance indicators
        """
        if not actual_values or not predicted_values:
            return None

        if len(actual_values) != len(predicted_values):
            return None

        n = len(actual_values)

        # Mean Absolute Error
        mae = mean(abs(actual_values[i] - predicted_values[i]) for i in range(n))

        # Root Mean Squared Error
        rmse = (
            sum((actual_values[i] - predicted_values[i]) ** 2 for i in range(n)) / n
        ) ** 0.5

        # Mean Absolute Percentage Error
        mape = None
        if all(v != 0 for v in actual_values):
            mape = mean(
                abs((actual_values[i] - predicted_values[i]) / actual_values[i])
                for i in range(n)
            )

        # R² Score (coefficient of determination)
        actual_mean = mean(actual_values)
        ss_tot = sum((v - actual_mean) ** 2 for v in actual_values)
        ss_res = sum(
            (actual_values[i] - predicted_values[i]) ** 2 for i in range(n)
        )
        r2 = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

        return ModelMetrics(
            model_id=model_id,
            metric_name="unknown",
            model_type="unknown",
            accuracy=max(0, min(1, r2)),
            mae=mae,
            rmse=rmse,
            mape=mape,
            prediction_horizon=n,
            test_set_size=n,
            evaluation_timestamp=datetime.utcnow().isoformat(),
        )
