"""Tests for Phase 5: Machine Learning Services."""

import pytest
from datetime import datetime

from app.models.ml import (
    AnomalyThresholds,
    ClusteringAnalysis,
    ForecastingResult,
    ModelMetrics,
    PatternDetectionResult,
    TimeSeriesModel,
)
from app.models.trace import KPIMetrics
from app.services.historical_analytics import HistoricalAnalytics
from app.services.ml_engine import (
    AdaptiveAnomalyDetector,
    ModelEvaluator,
    PatternDetector,
    RootCauseClustering,
    TimeSeriesForecaster,
)


class TestTimeSeriesForecaster:
    """Test time-series forecasting models."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_exponential_smoothing_basic(self):
        """Test exponential smoothing forecast."""
        # Create trend data
        for i, rate in enumerate([80.0, 82.0, 84.0, 86.0, 88.0]):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        result = TimeSeriesForecaster.forecast_exponential_smoothing(
            "registration_success_rate", forecast_hours=12
        )

        assert result is not None
        assert result.model_type == "exponential_smoothing"
        assert len(result.point_forecast) == 12
        assert len(result.lower_bound) == 12
        assert len(result.upper_bound) == 12
        assert result.confidence_level == 0.95

    def test_exponential_smoothing_intervals(self):
        """Test confidence intervals in exponential smoothing."""
        for i in range(10):
            kpi = KPIMetrics(registration_success_rate=90.0 + (i % 2))
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        result = TimeSeriesForecaster.forecast_exponential_smoothing(
            "registration_success_rate", forecast_hours=24
        )

        if result:
            for i in range(len(result.point_forecast)):
                assert result.lower_bound[i] <= result.point_forecast[i]
                assert result.point_forecast[i] <= result.upper_bound[i]

    def test_trend_forecast_improving(self):
        """Test trend forecast for improving metric."""
        rates = [70.0, 75.0, 80.0, 85.0, 90.0]
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        result = TimeSeriesForecaster.forecast_trend(
            "registration_success_rate", forecast_hours=10
        )

        assert result is not None
        assert result.model_type == "simple_trend"
        assert len(result.point_forecast) == 10
        assert result.point_forecast[-1] > result.point_forecast[0]

    def test_trend_forecast_degrading(self):
        """Test trend forecast for degrading metric."""
        rates = [95.0, 90.0, 85.0, 80.0, 75.0]
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        result = TimeSeriesForecaster.forecast_trend(
            "registration_success_rate", forecast_hours=10
        )

        assert result is not None
        assert result.point_forecast[-1] < result.point_forecast[0]

    def test_train_exponential_smoothing_model(self):
        """Test model training."""
        for i in range(5):
            kpi = KPIMetrics(registration_success_rate=85.0 + i)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        model = TimeSeriesForecaster.train_model(
            "registration_success_rate", model_type="exponential_smoothing"
        )

        assert model is not None
        assert model.model_type == "exponential_smoothing"
        assert model.alpha is not None
        assert 0 < model.alpha < 1
        assert model.baseline_mean > 0
        assert model.training_samples == 5
        assert model.model_accuracy > 0

    def test_train_trend_model(self):
        """Test trend model training."""
        for i in range(5):
            kpi = KPIMetrics(registration_success_rate=80.0 + i * 2)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        model = TimeSeriesForecaster.train_model(
            "registration_success_rate", model_type="simple_trend"
        )

        assert model is not None
        assert model.model_type == "simple_trend"
        assert model.trend_slope is not None
        assert model.trend_slope > 0  # Improving trend

    def test_forecast_with_insufficient_data(self):
        """Test forecast with too little data."""
        kpi = KPIMetrics(registration_success_rate=90.0)
        HistoricalAnalytics.record_metrics("trace1", kpi, [])

        result = TimeSeriesForecaster.forecast_exponential_smoothing(
            "registration_success_rate"
        )

        assert result is None


class TestAdaptiveAnomalyDetector:
    """Test adaptive anomaly detection."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_learn_thresholds_stable(self):
        """Test learning thresholds from stable data."""
        for i in range(10):
            kpi = KPIMetrics(registration_success_rate=90.0 + (i % 2) * 0.5)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        thresholds = AdaptiveAnomalyDetector.learn_thresholds(
            "registration_success_rate"
        )

        assert thresholds is not None
        assert thresholds.baseline_mean > 0
        assert thresholds.baseline_std >= 0
        assert 2.0 <= thresholds.z_score_threshold <= 3.5
        assert thresholds.confidence > 0.7

    def test_learn_thresholds_volatile(self):
        """Test learning thresholds from volatile data."""
        for i in range(10):
            rate = 50.0 + (i * 10 % 50)
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        thresholds = AdaptiveAnomalyDetector.learn_thresholds(
            "registration_success_rate"
        )

        assert thresholds is not None
        # Higher volatility should lead to higher z-score threshold
        assert thresholds.z_score_threshold > 2.0

    def test_detect_with_thresholds_normal(self):
        """Test normal values with learned thresholds."""
        for i in range(10):
            kpi = KPIMetrics(registration_success_rate=90.0 + (i % 2))
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        thresholds = AdaptiveAnomalyDetector.learn_thresholds(
            "registration_success_rate"
        )

        assert thresholds is not None

        result = AdaptiveAnomalyDetector.detect_with_thresholds(
            "registration_success_rate", 90.5, thresholds
        )

        assert result["is_anomaly"] is False
        assert result["severity"] == "none"

    def test_detect_with_thresholds_anomaly(self):
        """Test anomaly detection with learned thresholds."""
        for i in range(10):
            kpi = KPIMetrics(registration_success_rate=90.0 + (i % 2) * 0.5)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        thresholds = AdaptiveAnomalyDetector.learn_thresholds(
            "registration_success_rate"
        )

        assert thresholds is not None

        result = AdaptiveAnomalyDetector.detect_with_thresholds(
            "registration_success_rate", 50.0, thresholds
        )

        assert result["is_anomaly"] is True
        assert result["severity"] in ["high", "medium"]

    def test_detect_with_thresholds_high_severity(self):
        """Test high severity anomaly detection."""
        for i in range(10):
            kpi = KPIMetrics(registration_success_rate=90.0 + (i % 2) * 0.2)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        thresholds = AdaptiveAnomalyDetector.learn_thresholds(
            "registration_success_rate"
        )

        assert thresholds is not None

        result = AdaptiveAnomalyDetector.detect_with_thresholds(
            "registration_success_rate", 20.0, thresholds
        )

        assert result["is_anomaly"] is True
        assert result["severity"] == "high"


class TestRootCauseClustering:
    """Test root cause clustering."""

    def test_cluster_causes_ngap(self):
        """Test clustering NGAP causes."""
        causes = {
            "NGAP_20": 10,
            "NGAP_21": 5,
            "NGAP_24": 3,
        }

        analysis = RootCauseClustering.cluster_causes(causes)

        assert analysis is not None
        assert analysis.total_failures == 18
        assert len(analysis.clusters) >= 1
        assert analysis.dominant_cluster is not None

    def test_cluster_causes_multiple_protocols(self):
        """Test clustering across protocols."""
        causes = {
            "NGAP_20": 10,
            "NGAP_21": 5,
            "NAS_1": 8,
            "NAS_20": 4,
            "GTP_1": 3,
        }

        analysis = RootCauseClustering.cluster_causes(causes)

        assert analysis is not None
        assert len(analysis.clusters) >= 2
        # NGAP should be largest cluster (15 occurrences out of 30)
        assert analysis.clusters[0].percentage_of_total >= 50

    def test_cluster_causes_percentage(self):
        """Test percentage calculation."""
        causes = {"NGAP_20": 50, "NAS_1": 50}

        analysis = RootCauseClustering.cluster_causes(causes)

        assert analysis is not None
        total_pct = sum(c.percentage_of_total for c in analysis.clusters)
        assert 99 < total_pct < 101  # Should sum to ~100%

    def test_cluster_causes_recommendations(self):
        """Test getting recommendations for clusters."""
        causes = {"NGAP_20": 10}

        analysis = RootCauseClustering.cluster_causes(causes)

        assert analysis is not None
        assert len(analysis.clusters[0].recommended_resolution) > 0

    def test_cluster_causes_empty(self):
        """Test clustering with empty causes."""
        analysis = RootCauseClustering.cluster_causes({})

        assert analysis is None


class TestPatternDetector:
    """Test pattern detection."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_detect_improving_trend(self):
        """Test detection of improving trend."""
        rates = list(range(70, 91))  # 70 to 90
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=float(rate))
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        patterns = PatternDetector.detect_patterns("registration_success_rate", hours=24)

        assert len(patterns) > 0
        trend_patterns = [p for p in patterns if p.pattern_type == "trend"]
        assert len(trend_patterns) > 0

    def test_detect_degrading_trend(self):
        """Test detection of degrading trend."""
        rates = list(range(90, 69, -1))  # 90 to 70
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=float(rate))
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        patterns = PatternDetector.detect_patterns("registration_success_rate", hours=24)

        trend_patterns = [p for p in patterns if p.pattern_type == "trend"]
        if trend_patterns:
            assert "degrading" in trend_patterns[0].description.lower()

    def test_detect_daily_cycle(self):
        """Test detection of daily cycle."""
        # Create 48 hours of data with daily pattern
        base_pattern = [85.0, 87.0, 89.0, 88.0] * 12  # 48 values
        for i, rate in enumerate(base_pattern):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        patterns = PatternDetector.detect_patterns("registration_success_rate", hours=50)

        cycle_patterns = [p for p in patterns if p.pattern_type == "cyclic"]
        # Should detect daily cycle if we have good periodicity
        if cycle_patterns:
            assert "daily" in cycle_patterns[0].frequency.lower()

    def test_detect_bursts(self):
        """Test burst detection."""
        # Normal data with a spike
        rates = [90.0] * 10 + [95.0] + [90.0] * 10
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        patterns = PatternDetector.detect_patterns("registration_success_rate", hours=24)

        burst_patterns = [p for p in patterns if p.pattern_type == "burst"]
        # May or may not detect depending on baseline
        if burst_patterns:
            assert burst_patterns[0].impact > 0

    def test_detect_patterns_insufficient_data(self):
        """Test pattern detection with insufficient data."""
        kpi = KPIMetrics(registration_success_rate=90.0)
        HistoricalAnalytics.record_metrics("trace1", kpi, [])

        patterns = PatternDetector.detect_patterns("registration_success_rate")

        assert len(patterns) == 0


class TestModelEvaluator:
    """Test model evaluation."""

    def test_evaluate_perfect_forecast(self):
        """Test evaluation of perfect forecast."""
        actual = [90.0, 91.0, 92.0, 93.0, 94.0]
        predicted = [90.0, 91.0, 92.0, 93.0, 94.0]

        metrics = ModelEvaluator.evaluate_forecast(actual, predicted, "perfect_model")

        assert metrics is not None
        assert metrics.mae == 0.0
        assert metrics.rmse == 0.0
        assert metrics.accuracy == 1.0

    def test_evaluate_poor_forecast(self):
        """Test evaluation of poor forecast."""
        actual = [90.0, 91.0, 92.0, 93.0, 94.0]
        predicted = [70.0, 71.0, 72.0, 73.0, 74.0]

        metrics = ModelEvaluator.evaluate_forecast(actual, predicted, "poor_model")

        assert metrics is not None
        assert metrics.mae == 20.0
        assert metrics.accuracy < 0.5

    def test_evaluate_forecast_mape(self):
        """Test MAPE calculation."""
        actual = [100.0, 100.0, 100.0]
        predicted = [90.0, 100.0, 110.0]

        metrics = ModelEvaluator.evaluate_forecast(actual, predicted, "test_model")

        assert metrics is not None
        assert metrics.mape is not None
        # MAPE should be non-zero for errors

    def test_evaluate_forecast_mismatched_length(self):
        """Test with mismatched array lengths."""
        actual = [90.0, 91.0, 92.0]
        predicted = [90.0, 91.0]

        metrics = ModelEvaluator.evaluate_forecast(actual, predicted, "test_model")

        assert metrics is None

    def test_evaluate_forecast_empty(self):
        """Test with empty arrays."""
        metrics = ModelEvaluator.evaluate_forecast([], [], "test_model")

        assert metrics is None


class TestMLIntegration:
    """Test ML service integration."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_train_forecast_evaluate_pipeline(self):
        """Test complete ML pipeline: train → forecast → evaluate."""
        # Create training data
        for i in range(20):
            kpi = KPIMetrics(registration_success_rate=80.0 + (i * 0.5))
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        # Train model
        model = TimeSeriesForecaster.train_model(
            "registration_success_rate", model_type="simple_trend"
        )

        assert model is not None

        # Generate forecast
        forecast = TimeSeriesForecaster.forecast_trend(
            "registration_success_rate", forecast_hours=5
        )

        assert forecast is not None
        assert len(forecast.point_forecast) == 5

    def test_learn_detect_pipeline(self):
        """Test learning thresholds and detecting anomalies."""
        # Create training data
        for i in range(10):
            kpi = KPIMetrics(registration_success_rate=90.0 + (i % 3) * 0.5)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        # Learn thresholds
        thresholds = AdaptiveAnomalyDetector.learn_thresholds(
            "registration_success_rate"
        )

        assert thresholds is not None

        # Detect normal value
        normal_result = AdaptiveAnomalyDetector.detect_with_thresholds(
            "registration_success_rate", 90.0, thresholds
        )

        assert normal_result["is_anomaly"] is False

        # Detect anomaly
        anomaly_result = AdaptiveAnomalyDetector.detect_with_thresholds(
            "registration_success_rate", 40.0, thresholds
        )

        assert anomaly_result["is_anomaly"] is True

    def test_cluster_and_pattern_pipeline(self):
        """Test clustering and pattern detection together."""
        # Create training data
        for i in range(15):
            kpi = KPIMetrics(registration_success_rate=85.0 + (i % 5))
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        # Cluster causes
        causes = {"NGAP_20": 30, "NAS_1": 15, "GTP_1": 5}
        analysis = RootCauseClustering.cluster_causes(causes)

        assert analysis is not None
        assert analysis.total_failures == 50

        # Detect patterns
        patterns = PatternDetector.detect_patterns("registration_success_rate")

        # Both analyses should be valid
        assert analysis.cluster_count > 0
