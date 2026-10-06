"""Dashboard and visualization generation service.

Aggregates data from analytics services into charts, cards, and
dashboards for network operator visualization and monitoring.
"""

from datetime import datetime
from typing import Any

from app.models.dashboards import (
    AnomalyMarker,
    ChartData,
    ChartDataPoint,
    ComparisonMetric,
    CorrelationPair,
    DashboardWidget,
    ForecastBand,
    HealthScore,
    KPICard,
)
from app.models.ue_context import UEContext
from app.services.anomaly_detector import AnomalyDetector
from app.services.historical_analytics import HistoricalAnalytics
from app.services.predictive_analytics import PredictiveAnalytics


class DashboardGenerator:
    """Generates dashboard data for visualization.

    Converts analytics data into chart data, KPI cards, and
    visualization formats for dashboard display.
    """

    @staticmethod
    def generate_kpi_trend_chart(
        metric_name: str, hours: int = 24, title: str | None = None
    ) -> ChartData | None:
        """Generate trend chart for a metric.

        Args:
            metric_name: Metric to visualize
            hours: Time window
            title: Custom chart title

        Returns:
            ChartData ready for visualization
        """
        history = HistoricalAnalytics.get_history(metric_name, hours=hours)

        if not history:
            return None

        data_points = []
        for entry in history:
            if "value" in entry:
                data_points.append(
                    ChartDataPoint(
                        timestamp=entry["timestamp"],
                        value=entry["value"],
                    )
                )

        if not data_points:
            return None

        trend = HistoricalAnalytics.get_metric_trend(metric_name, hours=hours)
        current_value = data_points[-1].value if data_points else None

        return ChartData(
            chart_id=f"trend_{metric_name}_{hours}h",
            chart_type="line",
            title=title or f"{metric_name} Trend ({hours}h)",
            metric_name=metric_name,
            unit="%",
            data_points=data_points,
            current_value=current_value,
            trend_direction=trend.trend_direction if trend else None,
            metadata={
                "hours": hours,
                "data_points_count": len(data_points),
                "trend_confidence": trend.trend_confidence if trend else 0.0,
            },
        )

    @staticmethod
    def generate_kpi_cards(
        kpi_metrics: dict[str, Any],
    ) -> list[KPICard]:
        """Generate KPI cards for dashboard.

        Args:
            kpi_metrics: Current KPI metrics

        Returns:
            List of KPICard objects
        """
        cards = []

        # Registration success rate
        cards.append(
            DashboardGenerator._create_kpi_card(
                "registration_success_rate",
                kpi_metrics.get("registration_success_rate", 0),
                unit="%",
            )
        )

        # ICS success rate
        cards.append(
            DashboardGenerator._create_kpi_card(
                "ics_success_rate",
                kpi_metrics.get("ics_success_rate", 0),
                unit="%",
            )
        )

        # PDU session success rate
        cards.append(
            DashboardGenerator._create_kpi_card(
                "pdu_session_success_rate",
                kpi_metrics.get("pdu_session_success_rate", 0),
                unit="%",
            )
        )

        # Completion rate
        cards.append(
            DashboardGenerator._create_kpi_card(
                "completion_rate",
                kpi_metrics.get("completion_rate", 0),
                unit="%",
            )
        )

        return cards

    @staticmethod
    def _create_kpi_card(
        metric_name: str, current_value: float, unit: str = ""
    ) -> KPICard:
        """Create a single KPI card."""
        # Get trend
        trend = HistoricalAnalytics.get_metric_trend(metric_name, hours=24)

        # Determine status
        if metric_name.endswith("_rate"):
            status = "healthy" if current_value >= 90 else (
                "warning" if current_value >= 80 else "critical"
            )
        else:
            status = "healthy"

        # Get sparkline data
        history = HistoricalAnalytics.get_history(metric_name, hours=24, limit=20)
        sparkline = [h.get("value", 0) for h in history if "value" in h]

        return KPICard(
            metric_name=metric_name,
            current_value=current_value,
            unit=unit,
            trend=trend.trend_direction if trend else "stable",
            change_percentage=trend.change_percentage if trend else 0.0,
            status=status,
            sparkline_data=sparkline,
        )

    @staticmethod
    def generate_anomaly_chart(
        metric_name: str, hours: int = 24
    ) -> ChartData | None:
        """Generate chart with anomaly highlighting.

        Args:
            metric_name: Metric to analyze
            hours: Time window

        Returns:
            ChartData with anomaly markers
        """
        # Get trend chart
        chart = DashboardGenerator.generate_kpi_trend_chart(
            metric_name, hours=hours, title=f"{metric_name} with Anomalies"
        )

        if not chart:
            return None

        chart.chart_type = "area"

        # Add anomaly markers
        anomaly_markers = []
        for point in chart.data_points:
            score = AnomalyDetector.detect_anomaly(
                metric_name, point.value, hours=hours
            )

            if score and score.is_anomaly:
                anomaly_markers.append(
                    AnomalyMarker(
                        timestamp=point.timestamp,
                        value=point.value,
                        severity=score.severity,
                        description=f"z-score: {score.z_score:.2f}",
                        z_score=score.z_score,
                    )
                )

        chart.metadata["anomaly_markers"] = [
            m.model_dump() for m in anomaly_markers
        ]
        chart.metadata["anomaly_count"] = len(anomaly_markers)

        return chart

    @staticmethod
    def generate_forecast_chart(
        metric_name: str, forecast_hours: int = 24
    ) -> ChartData | None:
        """Generate chart with forecast bands.

        Args:
            metric_name: Metric to forecast
            forecast_hours: Hours ahead to forecast

        Returns:
            ChartData with forecast band
        """
        # Get historical trend
        trend = HistoricalAnalytics.get_metric_trend(metric_name, hours=24)

        if not trend:
            return None

        # Generate forecast chart
        chart = DashboardGenerator.generate_kpi_trend_chart(
            metric_name, hours=24, title=f"{metric_name} with Forecast"
        )

        if not chart:
            return None

        chart.chart_type = "area"

        # Create forecast band
        if chart.data_points:
            current_time = datetime.fromisoformat(
                chart.data_points[-1].timestamp.replace("Z", "+00:00")
            )
            from datetime import timedelta
            future_time = current_time + timedelta(hours=forecast_hours)

            # Simple projection based on trend
            current_val = chart.current_value or 0
            change_per_hour = trend.change_percentage / 24 if trend.data_points > 1 else 0
            projected_val = current_val + (change_per_hour * forecast_hours)

            forecast_band = ForecastBand(
                start_timestamp=chart.data_points[-1].timestamp,
                end_timestamp=future_time.isoformat(),
                lower_bound=max(0, projected_val - 10),
                upper_bound=min(100, projected_val + 10),
                expected_value=projected_val,
                probability=trend.trend_confidence,
                label=f"Forecast (+{forecast_hours}h)",
            )

            chart.metadata["forecast_band"] = forecast_band.model_dump()

        return chart

    @staticmethod
    def generate_procedure_comparison_chart() -> ChartData:
        """Generate comparison chart of all procedures.

        Returns:
            ChartData comparing registration, ICS, and PDU session
        """
        procedures = ["registration", "ics", "pdu_session"]
        data_points = []

        for proc in procedures:
            metric_name = f"{proc}_success_rate"
            stats = HistoricalAnalytics.get_statistics(metric_name, hours=24)

            if stats:
                data_points.append(
                    ChartDataPoint(
                        timestamp=datetime.utcnow().isoformat(),
                        value=stats["mean"],
                        metadata={"procedure": proc, "std_dev": stats["std_dev"]},
                    )
                )

        return ChartData(
            chart_id="procedure_comparison",
            chart_type="bar",
            title="Procedure Success Rate Comparison",
            unit="%",
            data_points=data_points,
            metadata={"procedures": procedures},
        )

    @staticmethod
    def generate_health_score(
        kpi_metrics: dict[str, Any], findings_count: int = 0
    ) -> HealthScore:
        """Generate overall network health score.

        Args:
            kpi_metrics: Current KPI metrics
            findings_count: Number of findings detected

        Returns:
            HealthScore with overall health status
        """
        # Component scores (0-100)
        reg_rate = kpi_metrics.get("registration_success_rate", 0)
        ics_rate = kpi_metrics.get("ics_success_rate", 0)
        pdu_rate = kpi_metrics.get("pdu_session_success_rate", 0)
        completion_rate = kpi_metrics.get("completion_rate", 0)

        # Calculate component scores
        components = {
            "registration": reg_rate,
            "ics": ics_rate,
            "pdu_session": pdu_rate,
            "completion": completion_rate,
        }

        # Overall score (weighted average)
        weights = {"registration": 0.25, "ics": 0.25, "pdu_session": 0.25, "completion": 0.25}
        overall_score = sum(
            components[key] * weights[key] for key in components
        )

        # Adjust for findings
        finding_penalty = min(20, findings_count * 2)
        overall_score = max(0, overall_score - finding_penalty)

        # Determine status
        if overall_score >= 90:
            status = "healthy"
        elif overall_score >= 70:
            status = "degraded"
        else:
            status = "critical"

        # Identify factors
        factors = []
        if reg_rate < 80:
            factors.append("Registration procedure issues")
        if ics_rate < 80:
            factors.append("ICS procedure degradation")
        if pdu_rate < 80:
            factors.append("PDU session setup failures")
        if completion_rate < 80:
            factors.append("Incomplete UE lifecycles")
        if findings_count > 5:
            factors.append(f"{findings_count} critical findings detected")

        return HealthScore(
            score=overall_score,
            status=status,
            components=components,
            last_update=datetime.utcnow().isoformat(),
            factors=factors,
        )

    @staticmethod
    def generate_metric_comparison(
        metric_name: str, time_period: str = "24h"
    ) -> ComparisonMetric | None:
        """Generate metric comparison (current vs previous period).

        Args:
            metric_name: Metric to compare
            time_period: Time period ("1h", "24h", "7d", "30d")

        Returns:
            ComparisonMetric with comparison data
        """
        hours_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
        hours = hours_map.get(time_period, 24)

        comparison = HistoricalAnalytics.get_comparison(metric_name, hours_ago=hours)

        if not comparison:
            return None

        current = comparison["current"]
        previous = comparison["historical"]
        change = comparison["change"]
        change_pct = comparison["change_percentage"]

        status = (
            "improved"
            if change > 0
            else ("degraded" if change < 0 else "stable")
        )

        return ComparisonMetric(
            metric_name=metric_name,
            current=current,
            previous=previous,
            change=change,
            change_percentage=change_pct,
            time_period=time_period,
            status=status,
        )

    @staticmethod
    def calculate_metric_correlation(
        metric_a: str, metric_b: str, hours: int = 24
    ) -> CorrelationPair | None:
        """Calculate correlation between two metrics.

        Args:
            metric_a: First metric
            metric_b: Second metric
            hours: Time window for analysis

        Returns:
            CorrelationPair with correlation analysis
        """
        history_a = HistoricalAnalytics.get_history(metric_a, hours=hours)
        history_b = HistoricalAnalytics.get_history(metric_b, hours=hours)

        if not history_a or not history_b or len(history_a) < 2:
            return None

        values_a = [h.get("value", 0) for h in history_a if "value" in h]
        values_b = [h.get("value", 0) for h in history_b if "value" in h]

        if len(values_a) != len(values_b) or len(values_a) < 2:
            return None

        # Calculate correlation coefficient
        mean_a = sum(values_a) / len(values_a)
        mean_b = sum(values_b) / len(values_b)

        numerator = sum(
            (values_a[i] - mean_a) * (values_b[i] - mean_b)
            for i in range(len(values_a))
        )

        var_a = sum((v - mean_a) ** 2 for v in values_a)
        var_b = sum((v - mean_b) ** 2 for v in values_b)

        denominator = (var_a * var_b) ** 0.5

        if denominator == 0:
            correlation = 0.0
        else:
            correlation = numerator / denominator

        # Determine strength
        abs_corr = abs(correlation)
        if abs_corr >= 0.7:
            strength = "strong"
        elif abs_corr >= 0.4:
            strength = "moderate"
        else:
            strength = "weak"

        description = (
            f"{'Positive' if correlation > 0 else 'Negative'} {strength} correlation: "
            f"when {metric_a} changes, {metric_b} tends to change in the "
            f"{'same' if correlation > 0 else 'opposite'} direction"
        )

        return CorrelationPair(
            metric_a=metric_a,
            metric_b=metric_b,
            correlation_coefficient=correlation,
            strength=strength,
            sample_size=len(values_a),
            description=description,
        )
