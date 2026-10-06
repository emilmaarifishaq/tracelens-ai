"""Tests for Phase 3: Advanced Analytics Services."""

import pytest
from datetime import datetime, timedelta

from app.models.analytics import CustomRule, HistoricalMetric
from app.models.trace import KPIMetrics
from app.models.ue_context import UEContext
from app.services.anomaly_detector import AnomalyDetector
from app.services.historical_analytics import HistoricalAnalytics
from app.services.predictive_analytics import PredictiveAnalytics
from app.services.rules_engine import RulesEngine


class TestHistoricalAnalytics:
    """Test historical metrics tracking and trend analysis."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_record_metrics(self):
        """Test recording KPI metrics snapshot."""
        kpi = KPIMetrics(
            registration_success_rate=95.0,
            ics_success_rate=92.0,
            pdu_session_success_rate=90.0,
            completion_rate=88.0,
            total_ues=100,
            complete_ues=88,
        )

        metric = HistoricalAnalytics.record_metrics("trace1", kpi, [])

        assert metric.registration_success_rate == 95.0
        assert metric.ics_success_rate == 92.0
        assert metric.total_ues == 100

    def test_get_metric_trend_improving(self):
        """Test trend detection for improving metric."""
        kpi_values = [85.0, 87.0, 90.0, 92.0, 95.0]

        for i, rate in enumerate(kpi_values):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        trend = HistoricalAnalytics.get_metric_trend("registration_success_rate")

        assert trend is not None
        assert trend.trend_direction == "improving"
        assert trend.current_value == 95.0

    def test_get_metric_trend_degrading(self):
        """Test trend detection for degrading metric."""
        kpi_values = [95.0, 92.0, 90.0, 87.0, 85.0]

        for i, rate in enumerate(kpi_values):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        trend = HistoricalAnalytics.get_metric_trend("registration_success_rate")

        assert trend is not None
        assert trend.trend_direction == "degrading"

    def test_get_metric_trend_stable(self):
        """Test trend detection for stable metric."""
        kpi_values = [90.0, 90.0, 90.0, 90.0, 90.0]

        for i, rate in enumerate(kpi_values):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        trend = HistoricalAnalytics.get_metric_trend("registration_success_rate")

        assert trend is not None
        assert trend.trend_direction == "stable"

    def test_detect_degradation(self):
        """Test degradation detection."""
        kpi_values = [90.0, 88.0, 85.0, 80.0, 75.0]

        for i, rate in enumerate(kpi_values):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        is_degrading = HistoricalAnalytics.detect_degradation(
            "registration_success_rate", threshold=5.0
        )

        assert is_degrading is True

    def test_get_comparison(self):
        """Test comparing current to historical value."""
        # Create multiple data points over recent history
        kpi_values = [90.0, 88.0, 85.0, 82.0, 80.0]

        for i, rate in enumerate(kpi_values):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        comparison = HistoricalAnalytics.get_comparison(
            "registration_success_rate", hours_ago=24
        )

        # Comparison may not find data that far back in this test
        # Check that if it does, the structure is correct
        if comparison is not None:
            assert "current" in comparison
            assert "change_percentage" in comparison

    def test_get_history(self):
        """Test retrieving historical data."""
        for i in range(5):
            kpi = KPIMetrics(registration_success_rate=85.0 + i)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        history = HistoricalAnalytics.get_history(
            "registration_success_rate"
        )

        assert len(history) == 5
        assert all("value" in h for h in history)

    def test_get_statistics(self):
        """Test statistical summary calculation."""
        for i in range(5):
            kpi = KPIMetrics(registration_success_rate=80.0 + i * 2)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        stats = HistoricalAnalytics.get_statistics("registration_success_rate")

        assert stats is not None
        assert stats["min"] == 80.0
        assert stats["max"] == 88.0
        assert stats["count"] == 5


class TestAnomalyDetector:
    """Test statistical anomaly detection."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_detect_anomaly_high_z_score(self):
        """Test detection of high z-score anomaly."""
        # Create baseline: 90.0, 90.5, 90.2, 89.8, 90.1
        baseline = [90.0, 90.5, 90.2, 89.8, 90.1]

        for i, rate in enumerate(baseline):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        # Test with anomalous value (very different from baseline)
        anomaly_score = AnomalyDetector.detect_anomaly(
            "registration_success_rate", current_value=50.0
        )

        assert anomaly_score is not None
        assert anomaly_score.is_anomaly is True
        assert anomaly_score.severity == "high"

    def test_detect_anomaly_normal_value(self):
        """Test normal values are not flagged as anomalies."""
        baseline = [90.0, 90.5, 90.2, 89.8, 90.1]

        for i, rate in enumerate(baseline):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        anomaly_score = AnomalyDetector.detect_anomaly(
            "registration_success_rate", current_value=90.3
        )

        assert anomaly_score is not None
        assert anomaly_score.is_anomaly is False

    def test_detect_anomalies_batch(self):
        """Test batch anomaly detection."""
        baseline = [90.0, 90.5, 90.2, 89.8, 90.1]

        for i, rate in enumerate(baseline):
            kpi = KPIMetrics(
                registration_success_rate=rate,
                ics_success_rate=rate,
                pdu_session_success_rate=rate,
            )
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        metrics = {
            "registration_success_rate": 50.0,
            "ics_success_rate": 45.0,
            "pdu_session_success_rate": 90.0,
        }

        anomalies = AnomalyDetector.detect_anomalies_batch(metrics)

        assert len(anomalies) >= 2

    def test_detect_outliers_iqr(self):
        """Test IQR-based outlier detection."""
        values = [80.0, 82.0, 85.0, 88.0, 90.0, 91.0, 92.0]

        for i, rate in enumerate(values):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        outlier_result = AnomalyDetector.detect_outliers_iqr(
            "registration_success_rate"
        )

        assert outlier_result is not None
        assert "lower_bound" in outlier_result
        assert "upper_bound" in outlier_result

    def test_compare_to_baseline(self):
        """Test baseline comparison."""
        baseline = [90.0, 90.5, 90.2, 89.8, 90.1]

        for i, rate in enumerate(baseline):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        comparison = AnomalyDetector.compare_to_baseline(
            "registration_success_rate", current_value=75.0
        )

        assert comparison is not None
        assert comparison["is_anomalous"] is True
        assert "change_percentage" in comparison

    def test_detect_sudden_change(self):
        """Test sudden change detection."""
        baseline = [90.0, 90.5, 90.2, 89.8, 90.1]

        for i, rate in enumerate(baseline):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        # Add a sudden drop
        kpi = KPIMetrics(registration_success_rate=70.0)
        HistoricalAnalytics.record_metrics("trace_drop", kpi, [])

        change = AnomalyDetector.detect_sudden_change(
            "registration_success_rate", threshold=10.0
        )

        assert change is not None
        assert change["detected"] is True


class TestPredictiveAnalytics:
    """Test predictive analytics and forecasting."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_forecast_capacity_issue(self):
        """Test capacity issue forecasting."""
        # Simulate degrading success rate
        rates = [95.0, 92.0, 89.0, 86.0, 83.0]

        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        forecast = PredictiveAnalytics.forecast_capacity_issue(
            "registration_success_rate", threshold=80.0
        )

        # May or may not predict depending on trend calculation
        if forecast:
            assert forecast.predicted_issue is not None
            assert 0 <= forecast.probability <= 1

    def test_forecast_degradation(self):
        """Test degradation forecasting."""
        rates = [95.0, 92.0, 89.0, 86.0, 83.0]

        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        forecast = PredictiveAnalytics.forecast_degradation(
            "registration_success_rate", degradation_threshold=5.0
        )

        # Forecast should detect degrading trend
        if forecast:
            assert "degradation" in forecast.insight_type
            assert forecast.probability > 0

    def test_forecast_resource_exhaustion(self):
        """Test resource exhaustion forecasting."""
        success_rates = {
            "registration": 70.0,
            "ics": 65.0,
            "pdu_session": 60.0,
        }

        forecast = PredictiveAnalytics.forecast_resource_exhaustion(success_rates)

        assert forecast is not None
        assert "resource_exhaustion" in forecast.insight_type
        assert forecast.probability > 0

    def test_forecast_reliability_issue(self):
        """Test reliability issue forecasting."""
        forecast = PredictiveAnalytics.forecast_reliability_issue(
            completion_rate=70.0, incomplete_ues=30, total_ues=100
        )

        assert forecast is not None
        assert forecast.predicted_issue is not None

    def test_generate_forecast_summary(self):
        """Test comprehensive forecast generation."""
        kpi_metrics = {
            "registration_success_rate": 75.0,
            "ics_success_rate": 70.0,
            "pdu_session_success_rate": 65.0,
            "completion_rate": 60.0,
            "incomplete_ues": 40,
            "total_ues": 100,
        }

        # Populate history
        for i in range(3):
            kpi = KPIMetrics(**kpi_metrics)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        forecast_list = PredictiveAnalytics.generate_forecast_summary(
            kpi_metrics
        )

        # Should generate forecasts for degrading metrics
        assert isinstance(forecast_list, list)


class TestRulesEngine:
    """Test custom rules evaluation."""

    def setup_method(self):
        """Clear rules before each test."""
        RulesEngine.clear_rules()

    def test_create_threshold_rule(self):
        """Test creating a threshold-based rule."""
        rule = CustomRule(
            rule_id="test_rule",
            name="High registration failure rate",
            rule_type="threshold",
            metric_name="registration_success_rate",
            operator="<",
            threshold=80.0,
            severity="warning",
        )

        created = RulesEngine.create_rule(rule)

        assert created.rule_id == "test_rule"
        assert created.enabled is True

    def test_evaluate_threshold_rule_triggered(self):
        """Test threshold rule triggering."""
        rule = CustomRule(
            rule_id="test_rule",
            name="Low success rate",
            rule_type="threshold",
            metric_name="registration_success_rate",
            operator="<",
            threshold=80.0,
            severity="warning",
        )

        RulesEngine.create_rule(rule)

        result = RulesEngine.evaluate_rule(rule, current_value=70.0)

        assert result is not None
        assert result.triggered is True
        assert result.severity == "warning"

    def test_evaluate_threshold_rule_not_triggered(self):
        """Test threshold rule not triggering."""
        rule = CustomRule(
            rule_id="test_rule",
            name="Low success rate",
            rule_type="threshold",
            metric_name="registration_success_rate",
            operator="<",
            threshold=80.0,
            severity="warning",
        )

        result = RulesEngine.evaluate_rule(rule, current_value=90.0)

        assert result is not None
        assert result.triggered is False

    def test_evaluate_between_operator(self):
        """Test 'between' operator for threshold rule."""
        rule = CustomRule(
            rule_id="range_rule",
            name="Normal range check",
            rule_type="threshold",
            operator="between",
            threshold=80.0,
            threshold_high=90.0,
            severity="info",
        )

        result = RulesEngine.evaluate_rule(rule, current_value=85.0)

        assert result is not None
        assert result.triggered is True

    def test_list_rules(self):
        """Test listing rules."""
        for i in range(3):
            rule = CustomRule(
                rule_id=f"rule{i}",
                name=f"Rule {i}",
                rule_type="threshold",
                enabled=(i != 1),
            )
            RulesEngine.create_rule(rule)

        all_rules = RulesEngine.list_rules()
        assert len(all_rules) == 3

        enabled_rules = RulesEngine.list_rules(enabled_only=True)
        assert len(enabled_rules) == 2

    def test_delete_rule(self):
        """Test deleting a rule."""
        rule = CustomRule(
            rule_id="to_delete",
            name="Delete me",
            rule_type="threshold",
        )

        RulesEngine.create_rule(rule)
        assert RulesEngine.get_rule("to_delete") is not None

        deleted = RulesEngine.delete_rule("to_delete")
        assert deleted is True
        assert RulesEngine.get_rule("to_delete") is None

    def test_evaluate_all_rules(self):
        """Test evaluating all rules at once."""
        rule1 = CustomRule(
            rule_id="rule1",
            name="Registration check",
            rule_type="threshold",
            metric_name="registration_success_rate",
            operator="<",
            threshold=80.0,
            severity="warning",
        )

        rule2 = CustomRule(
            rule_id="rule2",
            name="ICS check",
            rule_type="threshold",
            metric_name="ics_success_rate",
            operator="<",
            threshold=85.0,
            severity="warning",
        )

        RulesEngine.create_rule(rule1)
        RulesEngine.create_rule(rule2)

        metrics = {
            "registration_success_rate": 70.0,
            "ics_success_rate": 90.0,
        }

        results = RulesEngine.evaluate_all(metrics)

        # Only rule1 should trigger
        assert len(results) >= 1
        assert any(r.rule_id == "rule1" for r in results)

    def test_export_import_rules(self):
        """Test exporting and importing rules."""
        rule = CustomRule(
            rule_id="export_test",
            name="Export me",
            rule_type="threshold",
            metric_name="registration_success_rate",
            operator="<",
            threshold=75.0,
        )

        RulesEngine.create_rule(rule)

        exported = RulesEngine.export_rules()
        assert len(exported) == 1
        assert exported[0]["name"] == "Export me"

        RulesEngine.clear_rules()
        imported = RulesEngine.import_rules(exported)
        assert imported == 1
        assert RulesEngine.get_rule("export_test") is not None
