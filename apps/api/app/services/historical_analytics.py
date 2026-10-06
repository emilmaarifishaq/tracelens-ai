"""Historical analytics and trend detection service.

Tracks KPI metrics over time and identifies improving/degrading trends
for long-term network performance analysis.
"""

from datetime import datetime, timedelta
from typing import Any

from app.models.analytics import HistoricalMetric, MetricTrend
from app.models.trace import KPIMetrics
from app.models.ue_context import UEContext


class HistoricalAnalytics:
    """Tracks and analyzes historical KPI metrics.

    Maintains time-series data of KPI metrics for trend detection,
    degradation identification, and historical comparison.
    """

    # In-memory storage (would be replaced with database in production)
    _history: list[HistoricalMetric] = []

    @staticmethod
    def record_metrics(
        trace_id: str, kpi_metrics: KPIMetrics, contexts: list[UEContext]
    ) -> HistoricalMetric:
        """Record KPI metrics snapshot at current time.

        Args:
            trace_id: Unique trace identifier
            kpi_metrics: KPI metrics from Phase 2b
            contexts: UE contexts for additional context

        Returns:
            HistoricalMetric snapshot
        """
        # Calculate additional metrics
        avg_reg_time = kpi_metrics.procedure_timing.get("registration", {}).get("avg", 0.0)
        avg_ics_time = kpi_metrics.procedure_timing.get("ics", {}).get("avg", 0.0)
        avg_pdu_time = kpi_metrics.procedure_timing.get("pdu_session", {}).get("avg", 0.0)

        metric = HistoricalMetric(
            timestamp=datetime.utcnow(),
            trace_id=trace_id,
            registration_success_rate=kpi_metrics.registration_success_rate,
            ics_success_rate=kpi_metrics.ics_success_rate,
            pdu_session_success_rate=kpi_metrics.pdu_session_success_rate,
            completion_rate=kpi_metrics.completion_rate,
            avg_registration_time=avg_reg_time,
            avg_ics_time=avg_ics_time,
            avg_pdu_session_time=avg_pdu_time,
            total_ues=kpi_metrics.total_ues,
            complete_ues=kpi_metrics.complete_ues,
        )

        HistoricalAnalytics._history.append(metric)
        return metric

    @staticmethod
    def get_metric_trend(
        metric_name: str, hours: int = 24, min_data_points: int = 2
    ) -> MetricTrend | None:
        """Analyze trend for a specific metric over time period.

        Args:
            metric_name: Name of metric (e.g., "registration_success_rate")
            hours: Time period to analyze (default 24 hours)
            min_data_points: Minimum data points required

        Returns:
            MetricTrend with trend analysis, or None if insufficient data
        """
        if not HistoricalAnalytics._history:
            return None

        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)

        recent_metrics = [
            m for m in HistoricalAnalytics._history if m.timestamp >= cutoff
        ]

        if len(recent_metrics) < min_data_points:
            return None

        values = []
        for metric in sorted(recent_metrics, key=lambda m: m.timestamp):
            value = HistoricalAnalytics._get_metric_value(metric, metric_name)
            if value is not None:
                values.append(value)

        if len(values) < min_data_points:
            return None

        current = values[-1]
        previous = values[-2] if len(values) >= 2 else None
        change_pct = 0.0

        if previous is not None and previous != 0:
            change_pct = ((current - previous) / previous) * 100

        # Determine trend
        trend_direction = HistoricalAnalytics._calculate_trend(values)
        trend_confidence = HistoricalAnalytics._calculate_trend_confidence(values)

        return MetricTrend(
            metric_name=metric_name,
            current_value=current,
            previous_value=previous,
            trend_direction=trend_direction,
            trend_confidence=trend_confidence,
            change_percentage=change_pct,
            data_points=len(values),
            time_period_hours=float(hours),
        )

    @staticmethod
    def _get_metric_value(metric: HistoricalMetric, metric_name: str) -> float | None:
        """Extract metric value from HistoricalMetric."""
        metric_map = {
            "registration_success_rate": metric.registration_success_rate,
            "ics_success_rate": metric.ics_success_rate,
            "pdu_session_success_rate": metric.pdu_session_success_rate,
            "completion_rate": metric.completion_rate,
            "avg_registration_time": metric.avg_registration_time,
            "avg_ics_time": metric.avg_ics_time,
            "avg_pdu_session_time": metric.avg_pdu_session_time,
            "total_ues": float(metric.total_ues),
            "complete_ues": float(metric.complete_ues),
        }
        return metric_map.get(metric_name)

    @staticmethod
    def _calculate_trend(values: list[float]) -> str:
        """Determine trend direction from series of values.

        Uses simple linear regression to determine if metric is improving,
        degrading, or stable over time.
        """
        if len(values) < 2:
            return "stable"

        n = len(values)
        x_sum = n * (n - 1) / 2  # Sum of 0, 1, 2, ..., n-1
        y_sum = sum(values)
        xy_sum = sum(i * values[i] for i in range(n))
        x2_sum = n * (n - 1) * (2 * n - 1) / 6

        # Simple linear regression slope
        numerator = n * xy_sum - x_sum * y_sum
        denominator = n * x2_sum - x_sum * x_sum

        if denominator == 0:
            return "stable"

        slope = numerator / denominator

        # Success rates should improve (positive slope good)
        # Latency should decrease (negative slope good)
        if abs(slope) < 0.01:  # Threshold for "stable"
            return "stable"
        elif slope > 0:
            return "improving"
        else:
            return "degrading"

    @staticmethod
    def _calculate_trend_confidence(values: list[float]) -> float:
        """Calculate confidence in trend based on data consistency.

        Returns 0-1 confidence score. More consistent data = higher confidence.
        """
        if len(values) < 2:
            return 0.0

        # Calculate coefficient of variation
        mean = sum(values) / len(values)
        if mean == 0:
            return 0.0

        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        cv = std_dev / mean if mean != 0 else 0

        # Lower CV = higher confidence (0.0 = perfect consistency)
        # Confidence = 1 - (CV capped at 1.0)
        return max(0.0, min(1.0, 1.0 - cv))

    @staticmethod
    def detect_degradation(
        metric_name: str, hours: int = 24, threshold: float = 10.0
    ) -> bool:
        """Check if metric is degrading (change > threshold).

        Args:
            metric_name: Metric to check
            hours: Time period for trend
            threshold: Minimum % change to consider degradation

        Returns:
            True if degrading beyond threshold
        """
        trend = HistoricalAnalytics.get_metric_trend(metric_name, hours)
        if not trend:
            return False

        return (
            trend.trend_direction == "degrading"
            and abs(trend.change_percentage) >= threshold
        )

    @staticmethod
    def get_comparison(
        metric_name: str, hours_ago: int = 24
    ) -> dict[str, Any] | None:
        """Compare metric now vs. specific time ago.

        Args:
            metric_name: Metric to compare
            hours_ago: How far back to compare

        Returns:
            Comparison dictionary with current, previous, change
        """
        if not HistoricalAnalytics._history:
            return None

        now = datetime.utcnow()
        target_time = now - timedelta(hours=hours_ago)

        # Find most recent metric at target time
        historical = None
        for metric in reversed(HistoricalAnalytics._history):
            if metric.timestamp <= target_time:
                historical = metric
                break

        if not historical:
            return None

        # Get current metric
        current = HistoricalAnalytics._get_metric_value(
            HistoricalAnalytics._history[-1], metric_name
        )
        historical_val = HistoricalAnalytics._get_metric_value(
            historical, metric_name
        )

        if current is None or historical_val is None:
            return None

        change = current - historical_val
        change_pct = (change / historical_val * 100) if historical_val != 0 else 0

        return {
            "metric_name": metric_name,
            "current": current,
            "historical": historical_val,
            "change": change,
            "change_percentage": change_pct,
            "hours_ago": hours_ago,
            "current_timestamp": HistoricalAnalytics._history[-1].timestamp,
            "historical_timestamp": historical.timestamp,
        }

    @staticmethod
    def get_history(
        metric_name: str | None = None, hours: int = 24, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get historical metric data for analysis/visualization.

        Args:
            metric_name: Specific metric or None for all
            hours: Time window to retrieve
            limit: Maximum records to return

        Returns:
            List of metric snapshots with values
        """
        if not HistoricalAnalytics._history:
            return []

        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)

        recent = [
            m for m in HistoricalAnalytics._history if m.timestamp >= cutoff
        ][-limit:]

        result = []
        for metric in recent:
            entry = {
                "timestamp": metric.timestamp.isoformat(),
                "trace_id": metric.trace_id,
            }

            if metric_name:
                value = HistoricalAnalytics._get_metric_value(metric, metric_name)
                if value is not None:
                    entry["value"] = value
            else:
                entry["registration_success_rate"] = metric.registration_success_rate
                entry["ics_success_rate"] = metric.ics_success_rate
                entry["pdu_session_success_rate"] = metric.pdu_session_success_rate
                entry["completion_rate"] = metric.completion_rate
                entry["avg_registration_time"] = metric.avg_registration_time
                entry["avg_ics_time"] = metric.avg_ics_time
                entry["avg_pdu_session_time"] = metric.avg_pdu_session_time

            result.append(entry)

        return result

    @staticmethod
    def clear_history() -> None:
        """Clear historical data (for testing)."""
        HistoricalAnalytics._history.clear()

    @staticmethod
    def get_statistics(metric_name: str, hours: int = 24) -> dict[str, float] | None:
        """Get statistical summary of metric over time.

        Args:
            metric_name: Metric to analyze
            hours: Time period

        Returns:
            Dictionary with min, max, mean, median, std_dev
        """
        if not HistoricalAnalytics._history:
            return None

        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)

        values = []
        for metric in HistoricalAnalytics._history:
            if metric.timestamp >= cutoff:
                value = HistoricalAnalytics._get_metric_value(metric, metric_name)
                if value is not None:
                    values.append(value)

        if not values:
            return None

        values_sorted = sorted(values)
        n = len(values)
        mean = sum(values) / n
        median = (
            values_sorted[n // 2]
            if n % 2 == 1
            else (values_sorted[n // 2 - 1] + values_sorted[n // 2]) / 2
        )
        variance = sum((x - mean) ** 2 for x in values) / n
        std_dev = variance ** 0.5

        return {
            "min": min(values),
            "max": max(values),
            "mean": mean,
            "median": median,
            "std_dev": std_dev,
            "count": n,
        }
