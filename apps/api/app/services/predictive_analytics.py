"""Predictive analytics and forecasting service.

Forecasts future metric values and identifies potential issues
before they become critical.
"""

from typing import Any

from app.models.analytics import PredictiveInsight
from app.services.historical_analytics import HistoricalAnalytics


class PredictiveAnalytics:
    """Generates predictions about future metric values.

    Uses historical trends to forecast capacity issues and potential
    service degradation before they occur.
    """

    @staticmethod
    def forecast_capacity_issue(
        metric_name: str,
        threshold: float = 50.0,
        forecast_hours: int = 24,
    ) -> PredictiveInsight | None:
        """Forecast if metric will exceed/fall below threshold.

        Args:
            metric_name: Metric to forecast
            threshold: Critical threshold for the metric
            forecast_hours: Hours ahead to forecast

        Returns:
            PredictiveInsight if issue predicted, None otherwise
        """
        trend = HistoricalAnalytics.get_metric_trend(metric_name, hours=24)

        if not trend or trend.data_points < 3:
            return None

        # Use trend to extrapolate
        current = trend.current_value

        # Simple linear extrapolation
        change_per_hour = trend.change_percentage / 24 if trend.data_points > 1 else 0
        projected = current + (change_per_hour * forecast_hours)

        # Determine if threshold will be crossed
        # For success rates: low values are bad
        # For timing: high values are bad
        is_threshold_issue = False
        severity = "none"
        probability = 0.0

        if metric_name in [
            "registration_success_rate",
            "ics_success_rate",
            "pdu_session_success_rate",
            "completion_rate",
        ]:
            # For success rates, crossing below threshold is bad
            if projected < threshold and current >= threshold:
                is_threshold_issue = True
                severity = "critical" if threshold - projected > 20 else "warning"
                probability = min(
                    0.95, 0.5 + abs(threshold - projected) / 100
                )
        else:
            # For timing metrics, crossing above threshold is bad
            if projected > threshold and current <= threshold:
                is_threshold_issue = True
                severity = "critical" if projected - threshold > 1.0 else "warning"
                probability = min(
                    0.95, 0.5 + abs(projected - threshold) / 2
                )

        if not is_threshold_issue:
            return None

        # Determine root cause based on metric
        if "registration" in metric_name:
            predicted_issue = "Registration procedure may fail"
            actions = [
                "Review registration procedure configuration",
                "Check NAS server capacity and load",
                "Verify IMSI validation and security policies",
                "Monitor radio resource allocation",
            ]
        elif "ics" in metric_name:
            predicted_issue = "Initial Context Setup may fail"
            actions = [
                "Verify RAN resource availability",
                "Check bearer establishment procedures",
                "Review QoS configuration",
                "Monitor backhaul bandwidth",
            ]
        elif "pdu" in metric_name:
            predicted_issue = "PDU Session Setup may fail"
            actions = [
                "Verify SMF and UPF functionality",
                "Check session establishment procedures",
                "Review routing policies",
                "Monitor packet gateway resources",
            ]
        else:
            predicted_issue = f"Metric {metric_name} may degrade beyond threshold"
            actions = [
                f"Investigate trend in {metric_name}",
                "Check resource utilization",
                "Review recent configuration changes",
            ]

        return PredictiveInsight(
            insight_type="capacity_forecast",
            predicted_issue=predicted_issue,
            probability=probability,
            time_horizon_hours=forecast_hours,
            recommended_actions=actions,
            confidence=trend.trend_confidence,
            details={
                "metric_name": metric_name,
                "current_value": current,
                "projected_value": projected,
                "threshold": threshold,
                "trend_direction": trend.trend_direction,
                "change_percentage": trend.change_percentage,
            },
        )

    @staticmethod
    def forecast_degradation(
        metric_name: str, degradation_threshold: float = 10.0
    ) -> PredictiveInsight | None:
        """Forecast if metric will degrade beyond threshold.

        Args:
            metric_name: Metric to analyze
            degradation_threshold: % change threshold to warn about

        Returns:
            PredictiveInsight if degradation predicted
        """
        trend = HistoricalAnalytics.get_metric_trend(metric_name, hours=24)

        if not trend or trend.trend_direction == "improving":
            return None

        if abs(trend.change_percentage) < degradation_threshold:
            return None

        # Forecast next 24 hours based on current trend
        projected_change = trend.change_percentage * 1.2  # 20% amplification

        probability = min(0.95, 0.6 + abs(trend.change_percentage) / 100)

        return PredictiveInsight(
            insight_type="degradation_forecast",
            predicted_issue=f"{metric_name} showing degradation trend, may worsen",
            probability=probability,
            time_horizon_hours=24,
            recommended_actions=[
                f"Investigate cause of {metric_name} degradation",
                "Check for resource constraints or congestion",
                "Review recent changes to configuration",
                f"Monitor {metric_name} closely for continued decline",
                "Prepare escalation procedures if needed",
            ],
            confidence=trend.trend_confidence,
            details={
                "metric_name": metric_name,
                "current_change_percentage": trend.change_percentage,
                "projected_change_percentage": projected_change,
                "trend_direction": trend.trend_direction,
                "data_points": trend.data_points,
            },
        )

    @staticmethod
    def forecast_resource_exhaustion(
        success_rate_metrics: dict[str, float], forecast_hours: int = 12
    ) -> PredictiveInsight | None:
        """Forecast if resources may be exhausted.

        Args:
            success_rate_metrics: Dict of procedure success rates
            forecast_hours: Hours ahead to forecast

        Returns:
            PredictiveInsight if exhaustion predicted
        """
        low_success_metrics = [
            (name, rate)
            for name, rate in success_rate_metrics.items()
            if rate < 80.0
        ]

        if len(low_success_metrics) < 2:
            return None

        # Multiple procedures failing indicates resource issues
        avg_rate = sum(rate for _, rate in low_success_metrics) / len(
            low_success_metrics
        )

        # Project forward
        degradation_rate = (100 - avg_rate) / 100
        projected_rate = max(0, avg_rate - (degradation_rate * 5))

        probability = min(0.90, 0.5 + (100 - avg_rate) / 200)

        return PredictiveInsight(
            insight_type="resource_exhaustion_forecast",
            predicted_issue="Multiple procedures failing, resource exhaustion likely",
            probability=probability,
            time_horizon_hours=forecast_hours,
            recommended_actions=[
                "Immediately assess network resource utilization",
                "Check radio resource blocks (RRB) availability",
                "Verify bearer/session quotas and limits",
                "Review admission control thresholds",
                "Consider load balancing or traffic steering",
                "Prepare capacity expansion if needed",
            ],
            confidence=0.85,
            details={
                "affected_procedures": list(
                    name for name, _ in low_success_metrics
                ),
                "current_average_success_rate": avg_rate,
                "projected_success_rate": projected_rate,
                "forecast_period_hours": forecast_hours,
            },
        )

    @staticmethod
    def forecast_reliability_issue(
        completion_rate: float, incomplete_ues: int, total_ues: int
    ) -> PredictiveInsight | None:
        """Forecast reliability issues based on incomplete lifecycles.

        Args:
            completion_rate: % of complete UE lifecycles
            incomplete_ues: Count of incomplete UEs
            total_ues: Total UEs analyzed

        Returns:
            PredictiveInsight if reliability issue predicted
        """
        if completion_rate >= 95:
            return None

        # Estimate if trend continues
        incomplete_rate = (total_ues - incomplete_ues) / total_ues
        projected_incomplete = max(0, incomplete_rate - 0.05)

        probability = min(0.85, 0.6 + (100 - completion_rate) / 200)

        return PredictiveInsight(
            insight_type="reliability_forecast",
            predicted_issue="Incomplete UE lifecycles indicate potential disconnections",
            probability=probability,
            time_horizon_hours=24,
            recommended_actions=[
                "Investigate UE disconnection/release patterns",
                "Check radio link failure handling",
                "Verify UE idle/inactive state management",
                "Review RRC connection release triggers",
                "Monitor for network-initiated disconnections",
                "Check for resource leaks in network elements",
            ],
            confidence=0.80,
            details={
                "completion_rate": completion_rate,
                "incomplete_ues": incomplete_ues,
                "total_ues": total_ues,
                "incomplete_rate_percentage": (1 - completion_rate) * 100,
                "projected_incomplete_rate": projected_incomplete * 100,
            },
        )

    @staticmethod
    def generate_forecast_summary(
        kpi_metrics: dict[str, Any],
    ) -> list[PredictiveInsight]:
        """Generate comprehensive forecast based on current metrics.

        Args:
            kpi_metrics: Current KPI metrics

        Returns:
            List of PredictiveInsights sorted by probability
        """
        insights: list[PredictiveInsight] = []

        # Forecast capacity issues
        capacity_insight = PredictiveAnalytics.forecast_capacity_issue(
            "registration_success_rate", threshold=80.0
        )
        if capacity_insight:
            insights.append(capacity_insight)

        capacity_insight = PredictiveAnalytics.forecast_capacity_issue(
            "ics_success_rate", threshold=85.0
        )
        if capacity_insight:
            insights.append(capacity_insight)

        capacity_insight = PredictiveAnalytics.forecast_capacity_issue(
            "pdu_session_success_rate", threshold=80.0
        )
        if capacity_insight:
            insights.append(capacity_insight)

        # Forecast degradation
        deg_insight = PredictiveAnalytics.forecast_degradation(
            "completion_rate", degradation_threshold=5.0
        )
        if deg_insight:
            insights.append(deg_insight)

        # Forecast resource exhaustion
        success_rates = {
            "registration": kpi_metrics.get("registration_success_rate", 100),
            "ics": kpi_metrics.get("ics_success_rate", 100),
            "pdu_session": kpi_metrics.get("pdu_session_success_rate", 100),
        }
        res_insight = PredictiveAnalytics.forecast_resource_exhaustion(
            success_rates
        )
        if res_insight:
            insights.append(res_insight)

        # Forecast reliability
        rel_insight = PredictiveAnalytics.forecast_reliability_issue(
            kpi_metrics.get("completion_rate", 100),
            kpi_metrics.get("incomplete_ues", 0),
            kpi_metrics.get("total_ues", 1),
        )
        if rel_insight:
            insights.append(rel_insight)

        # Sort by probability
        insights.sort(key=lambda i: i.probability, reverse=True)

        return insights
