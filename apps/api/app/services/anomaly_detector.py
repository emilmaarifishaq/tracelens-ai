"""Statistical anomaly detection service.

Identifies anomalous metric values using statistical methods (z-score, IQR)
without requiring predefined thresholds.
"""

from typing import Any

from app.models.analytics import AnomalyScore
from app.services.historical_analytics import HistoricalAnalytics


class AnomalyDetector:
    """Detects anomalies in metrics using statistical methods.

    Analyzes metric distributions to identify values that deviate
    significantly from normal patterns.
    """

    # Z-score thresholds for anomaly severity
    Z_SCORE_THRESHOLD_HIGH = 3.0  # Severe anomaly
    Z_SCORE_THRESHOLD_MEDIUM = 2.5  # Moderate anomaly
    Z_SCORE_THRESHOLD_LOW = 2.0  # Mild anomaly

    @staticmethod
    def detect_anomaly(
        metric_name: str, current_value: float, hours: int = 24
    ) -> AnomalyScore | None:
        """Detect if current metric value is anomalous.

        Uses z-score method to identify values that deviate significantly
        from historical distribution.

        Args:
            metric_name: Metric to analyze
            current_value: Current metric value
            hours: Historical window to use for baseline

        Returns:
            AnomalyScore with detection result, or None if insufficient data
        """
        stats = HistoricalAnalytics.get_statistics(metric_name, hours)

        if not stats or stats["count"] < 3:
            return None

        mean = stats["mean"]
        std_dev = stats["std_dev"]

        # Handle edge case of zero standard deviation
        if std_dev == 0:
            # All historical values are the same
            is_anomaly = current_value != mean
            z_score = float("inf") if is_anomaly else 0.0
        else:
            z_score = (current_value - mean) / std_dev
            is_anomaly = abs(z_score) >= AnomalyDetector.Z_SCORE_THRESHOLD_LOW

        # Determine severity
        if abs(z_score) >= AnomalyDetector.Z_SCORE_THRESHOLD_HIGH:
            severity = "high"
            confidence = 0.95
        elif abs(z_score) >= AnomalyDetector.Z_SCORE_THRESHOLD_MEDIUM:
            severity = "medium"
            confidence = 0.85
        elif abs(z_score) >= AnomalyDetector.Z_SCORE_THRESHOLD_LOW:
            severity = "low"
            confidence = 0.75
        else:
            severity = "none"
            is_anomaly = False
            confidence = 0.95

        return AnomalyScore(
            metric_name=metric_name,
            metric_value=current_value,
            expected_value=mean,
            z_score=z_score,
            is_anomaly=is_anomaly,
            severity=severity,
            confidence=confidence,
            details={
                "historical_mean": mean,
                "historical_std_dev": std_dev,
                "deviations_from_mean": abs(z_score),
                "data_points_in_baseline": stats["count"],
            },
        )

    @staticmethod
    def detect_anomalies_batch(
        metrics: dict[str, float], hours: int = 24
    ) -> list[AnomalyScore]:
        """Detect anomalies in multiple metrics at once.

        Args:
            metrics: Dictionary of metric_name -> value
            hours: Historical window

        Returns:
            List of AnomalyScores for anomalies found
        """
        anomalies = []

        for metric_name, value in metrics.items():
            score = AnomalyDetector.detect_anomaly(metric_name, value, hours)
            if score and score.is_anomaly:
                anomalies.append(score)

        # Sort by severity and z-score
        severity_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
        anomalies.sort(
            key=lambda a: (severity_order[a.severity], -abs(a.z_score))
        )

        return anomalies

    @staticmethod
    def detect_outliers_iqr(
        metric_name: str, hours: int = 24, k: float = 1.5
    ) -> dict[str, Any] | None:
        """Detect outliers using Interquartile Range (IQR) method.

        Alternative to z-score that's more robust to extreme values.

        Args:
            metric_name: Metric to analyze
            hours: Historical window
            k: IQR multiplier (default 1.5 for standard outliers, 3.0 for extreme)

        Returns:
            Dictionary with outlier bounds and status, or None if insufficient data
        """
        stats = HistoricalAnalytics.get_statistics(metric_name, hours)

        if not stats or stats["count"] < 4:
            return None

        history = HistoricalAnalytics.get_history(metric_name, hours)
        if not history:
            return None

        values = [h.get("value") for h in history if "value" in h]
        values = sorted([v for v in values if v is not None])

        if len(values) < 4:
            return None

        # Calculate quartiles
        n = len(values)
        q1_idx = n // 4
        q3_idx = (3 * n) // 4

        q1 = values[q1_idx]
        q3 = values[q3_idx]
        iqr = q3 - q1

        lower_bound = q1 - k * iqr
        upper_bound = q3 + k * iqr

        current = values[-1]
        is_outlier = current < lower_bound or current > upper_bound

        return {
            "metric_name": metric_name,
            "current_value": current,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "q1": q1,
            "q3": q3,
            "iqr": iqr,
            "is_outlier": is_outlier,
            "direction": "too_low" if current < lower_bound else "too_high" if current > upper_bound else "normal",
        }

    @staticmethod
    def compare_to_baseline(
        metric_name: str, current_value: float, baseline_hours: int = 168
    ) -> dict[str, Any] | None:
        """Compare current value to baseline (e.g., last week).

        Args:
            metric_name: Metric to analyze
            current_value: Current metric value
            baseline_hours: How far back for baseline (default 1 week)

        Returns:
            Comparison with current vs baseline
        """
        baseline_stats = HistoricalAnalytics.get_statistics(
            metric_name, baseline_hours
        )

        if not baseline_stats:
            return None

        baseline_mean = baseline_stats["mean"]
        baseline_std = baseline_stats["std_dev"]

        if baseline_mean == 0:
            change_pct = 0.0
        else:
            change_pct = ((current_value - baseline_mean) / baseline_mean) * 100

        deviation_sigmas = (
            (current_value - baseline_mean) / baseline_std
            if baseline_std > 0
            else 0
        )

        # Determine if anomalous compared to baseline
        is_anomalous = abs(deviation_sigmas) > 2.0

        return {
            "metric_name": metric_name,
            "current_value": current_value,
            "baseline_mean": baseline_mean,
            "baseline_std": baseline_std,
            "change_percentage": change_pct,
            "deviation_sigmas": deviation_sigmas,
            "is_anomalous": is_anomalous,
            "baseline_period_hours": baseline_hours,
        }

    @staticmethod
    def detect_sudden_change(
        metric_name: str, threshold: float = 5.0, look_back: int = 5
    ) -> dict[str, Any] | None:
        """Detect sudden changes in metric values.

        Identifies abrupt changes in recent data points.

        Args:
            metric_name: Metric to analyze
            threshold: Minimum % change to detect
            look_back: Number of recent points to compare

        Returns:
            Change detection result, or None if no sudden change
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=24)

        if len(history) < look_back:
            return None

        recent = history[-look_back:]
        values = [h.get("value") for h in recent if "value" in h]

        if len(values) < 2:
            return None

        current = values[-1]
        previous_avg = sum(values[:-1]) / (len(values) - 1)

        if previous_avg == 0:
            change_pct = 0.0
        else:
            change_pct = ((current - previous_avg) / previous_avg) * 100

        detected = abs(change_pct) >= threshold

        return {
            "metric_name": metric_name,
            "current_value": current,
            "previous_average": previous_avg,
            "change_percentage": change_pct,
            "threshold": threshold,
            "detected": detected,
            "direction": "increased" if change_pct > 0 else "decreased",
        }
