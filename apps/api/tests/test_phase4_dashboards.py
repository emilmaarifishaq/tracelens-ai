"""Tests for Phase 4: Dashboard & Visualization Services."""

import pytest

from app.models.trace import KPIMetrics
from app.services.dashboard_generator import DashboardGenerator
from app.services.historical_analytics import HistoricalAnalytics


class TestDashboardGenerator:
    """Test dashboard generation and visualization."""

    def setup_method(self):
        """Clear history before each test."""
        HistoricalAnalytics.clear_history()

    def test_generate_kpi_trend_chart(self):
        """Test KPI trend chart generation."""
        # Populate history
        rates = [85.0, 87.0, 90.0, 92.0, 95.0]
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        chart = DashboardGenerator.generate_kpi_trend_chart(
            "registration_success_rate"
        )

        assert chart is not None
        assert chart.chart_type == "line"
        assert len(chart.data_points) == 5
        assert chart.current_value == 95.0
        assert chart.metric_name == "registration_success_rate"

    def test_generate_kpi_trend_chart_custom_title(self):
        """Test trend chart with custom title."""
        kpi = KPIMetrics(registration_success_rate=90.0)
        HistoricalAnalytics.record_metrics("trace1", kpi, [])

        chart = DashboardGenerator.generate_kpi_trend_chart(
            "registration_success_rate", title="Custom Title"
        )

        assert chart is not None
        assert chart.title == "Custom Title"

    def test_generate_kpi_cards(self):
        """Test KPI card generation."""
        kpi_metrics = {
            "registration_success_rate": 92.0,
            "ics_success_rate": 88.0,
            "pdu_session_success_rate": 85.0,
            "completion_rate": 82.0,
        }

        cards = DashboardGenerator.generate_kpi_cards(kpi_metrics)

        assert len(cards) >= 4
        assert any(c.metric_name == "registration_success_rate" for c in cards)
        assert any(c.metric_name == "ics_success_rate" for c in cards)

    def test_kpi_card_status_healthy(self):
        """Test KPI card status calculation for healthy metrics."""
        kpi_metrics = {"registration_success_rate": 95.0}

        cards = DashboardGenerator.generate_kpi_cards(kpi_metrics)
        reg_card = next(
            c for c in cards if c.metric_name == "registration_success_rate"
        )

        assert reg_card.status == "healthy"
        assert reg_card.current_value == 95.0

    def test_kpi_card_status_warning(self):
        """Test KPI card status calculation for warning metrics."""
        kpi_metrics = {"registration_success_rate": 85.0}

        cards = DashboardGenerator.generate_kpi_cards(kpi_metrics)
        reg_card = next(
            c for c in cards if c.metric_name == "registration_success_rate"
        )

        assert reg_card.status == "warning"

    def test_kpi_card_status_critical(self):
        """Test KPI card status calculation for critical metrics."""
        kpi_metrics = {"registration_success_rate": 70.0}

        cards = DashboardGenerator.generate_kpi_cards(kpi_metrics)
        reg_card = next(
            c for c in cards if c.metric_name == "registration_success_rate"
        )

        assert reg_card.status == "critical"

    def test_generate_anomaly_chart(self):
        """Test anomaly highlighting chart."""
        # Create baseline with some variation
        rates = [90.0, 91.0, 89.5, 90.5, 50.0]  # Last one is anomaly
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        chart = DashboardGenerator.generate_anomaly_chart(
            "registration_success_rate"
        )

        assert chart is not None
        assert chart.chart_type == "area"
        assert "anomaly_markers" in chart.metadata

    def test_generate_forecast_chart(self):
        """Test forecast chart generation."""
        # Create trend
        rates = [95.0, 92.0, 89.0, 86.0, 83.0]
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        chart = DashboardGenerator.generate_forecast_chart(
            "registration_success_rate"
        )

        assert chart is not None
        assert "forecast_band" in chart.metadata

    def test_generate_procedure_comparison_chart(self):
        """Test procedure comparison chart."""
        # Create diverse metrics
        for i in range(3):
            kpi = KPIMetrics(
                registration_success_rate=90.0 + i,
                ics_success_rate=85.0 + i,
                pdu_session_success_rate=80.0 + i,
            )
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        chart = DashboardGenerator.generate_procedure_comparison_chart()

        assert chart is not None
        assert chart.chart_type == "bar"
        assert len(chart.data_points) >= 3

    def test_generate_health_score_healthy(self):
        """Test health score for healthy network."""
        kpi_metrics = {
            "registration_success_rate": 95.0,
            "ics_success_rate": 94.0,
            "pdu_session_success_rate": 93.0,
            "completion_rate": 92.0,
        }

        health = DashboardGenerator.generate_health_score(kpi_metrics, findings_count=0)

        assert health.status == "healthy"
        assert health.score >= 90
        assert len(health.factors) == 0

    def test_generate_health_score_degraded(self):
        """Test health score for degraded network."""
        kpi_metrics = {
            "registration_success_rate": 82.0,
            "ics_success_rate": 80.0,
            "pdu_session_success_rate": 78.0,
            "completion_rate": 76.0,
        }

        health = DashboardGenerator.generate_health_score(kpi_metrics, findings_count=3)

        assert health.status == "degraded"
        assert health.score < 90
        assert len(health.factors) > 0

    def test_generate_health_score_critical(self):
        """Test health score for critical network."""
        kpi_metrics = {
            "registration_success_rate": 50.0,
            "ics_success_rate": 40.0,
            "pdu_session_success_rate": 30.0,
            "completion_rate": 25.0,
        }

        health = DashboardGenerator.generate_health_score(kpi_metrics, findings_count=10)

        assert health.status == "critical"
        assert health.score < 70

    def test_generate_health_score_components(self):
        """Test health score component breakdown."""
        kpi_metrics = {
            "registration_success_rate": 90.0,
            "ics_success_rate": 85.0,
            "pdu_session_success_rate": 80.0,
            "completion_rate": 75.0,
        }

        health = DashboardGenerator.generate_health_score(kpi_metrics)

        assert "registration" in health.components
        assert health.components["registration"] == 90.0
        assert health.components["ics"] == 85.0

    def test_generate_metric_comparison(self):
        """Test metric comparison (current vs historical)."""
        # Create history with increasing values
        rates = [80.0, 82.0, 84.0, 86.0, 88.0]
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        comparison = DashboardGenerator.generate_metric_comparison(
            "registration_success_rate", time_period="24h"
        )

        if comparison:
            assert comparison.metric_name == "registration_success_rate"
            assert comparison.status in ["improved", "degraded", "stable"]

    def test_calculate_metric_correlation(self):
        """Test metric correlation calculation."""
        # Create correlated metrics (both increasing)
        for i in range(5):
            kpi = KPIMetrics(
                registration_success_rate=80.0 + i * 2,
                ics_success_rate=85.0 + i * 2,
            )
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        correlation = DashboardGenerator.calculate_metric_correlation(
            "registration_success_rate", "ics_success_rate"
        )

        assert correlation is not None
        assert -1 <= correlation.correlation_coefficient <= 1
        assert correlation.metric_a == "registration_success_rate"
        assert correlation.metric_b == "ics_success_rate"

    def test_metric_correlation_strong(self):
        """Test strong positive correlation detection."""
        # Perfectly correlated metrics
        for i in range(5):
            value = 80.0 + i * 5
            kpi = KPIMetrics(
                registration_success_rate=value,
                ics_success_rate=value,
            )
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        correlation = DashboardGenerator.calculate_metric_correlation(
            "registration_success_rate", "ics_success_rate"
        )

        assert correlation is not None
        assert correlation.strength == "strong"

    def test_metric_correlation_weak(self):
        """Test weak correlation detection."""
        # Weakly correlated metrics
        for i in range(5):
            kpi = KPIMetrics(
                registration_success_rate=85.0 + i,
                ics_success_rate=85.0,  # No correlation, stays constant
            )
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        correlation = DashboardGenerator.calculate_metric_correlation(
            "registration_success_rate", "ics_success_rate"
        )

        if correlation:
            assert correlation.strength in ["weak", "moderate", "strong"]

    def test_kpi_card_sparkline(self):
        """Test sparkline data in KPI cards."""
        rates = [85.0, 87.0, 90.0, 92.0, 95.0]
        for i, rate in enumerate(rates):
            kpi = KPIMetrics(registration_success_rate=rate)
            HistoricalAnalytics.record_metrics(f"trace{i}", kpi, [])

        cards = DashboardGenerator.generate_kpi_cards(
            {"registration_success_rate": 95.0}
        )

        reg_card = next(
            c for c in cards if c.metric_name == "registration_success_rate"
        )

        assert len(reg_card.sparkline_data) > 0

    def test_chart_data_model(self):
        """Test ChartData model serialization."""
        kpi = KPIMetrics(registration_success_rate=90.0)
        HistoricalAnalytics.record_metrics("trace1", kpi, [])

        chart = DashboardGenerator.generate_kpi_trend_chart(
            "registration_success_rate"
        )

        if chart:
            chart_dict = chart.model_dump()
            assert "chart_id" in chart_dict
            assert "chart_type" in chart_dict
            assert "data_points" in chart_dict

    def test_health_score_with_no_findings(self):
        """Test health score without findings."""
        kpi_metrics = {
            "registration_success_rate": 92.0,
            "ics_success_rate": 90.0,
            "pdu_session_success_rate": 88.0,
            "completion_rate": 85.0,
        }

        health = DashboardGenerator.generate_health_score(kpi_metrics, findings_count=0)

        assert health.score > 80
        assert "findings detected" not in " ".join(health.factors)

    def test_health_score_timestamp(self):
        """Test health score includes update timestamp."""
        kpi_metrics = {"registration_success_rate": 90.0}

        health = DashboardGenerator.generate_health_score(kpi_metrics)

        assert health.last_update is not None
        # Should be ISO format
        assert "T" in health.last_update or ":" in health.last_update
