"""Custom rules engine for user-defined trace analysis rules.

Allows network operators to define custom thresholds and conditions
for detecting issues specific to their network.
"""

from typing import Any

from app.models.analytics import CustomRule, CustomRuleResult
from app.services.anomaly_detector import AnomalyDetector
from app.services.historical_analytics import HistoricalAnalytics


class RulesEngine:
    """Evaluates custom rules against metrics.

    Supports threshold-based, trend-based, anomaly-based, and
    composite rules for flexible issue detection.
    """

    # In-memory rule storage (would be database in production)
    _rules: dict[str, CustomRule] = {}

    @staticmethod
    def create_rule(rule: CustomRule) -> CustomRule:
        """Create a new custom rule.

        Args:
            rule: CustomRule to create

        Returns:
            Created rule with ID
        """
        if not rule.rule_id:
            rule.rule_id = f"rule_{len(RulesEngine._rules) + 1}"

        RulesEngine._rules[rule.rule_id] = rule
        return rule

    @staticmethod
    def update_rule(rule_id: str, rule: CustomRule) -> CustomRule | None:
        """Update an existing rule.

        Args:
            rule_id: ID of rule to update
            rule: Updated rule data

        Returns:
            Updated rule or None if not found
        """
        if rule_id not in RulesEngine._rules:
            return None

        rule.rule_id = rule_id
        RulesEngine._rules[rule_id] = rule
        return rule

    @staticmethod
    def delete_rule(rule_id: str) -> bool:
        """Delete a rule.

        Args:
            rule_id: ID of rule to delete

        Returns:
            True if deleted, False if not found
        """
        if rule_id not in RulesEngine._rules:
            return False

        del RulesEngine._rules[rule_id]
        return True

    @staticmethod
    def get_rule(rule_id: str) -> CustomRule | None:
        """Get a rule by ID."""
        return RulesEngine._rules.get(rule_id)

    @staticmethod
    def list_rules(enabled_only: bool = False) -> list[CustomRule]:
        """List all rules.

        Args:
            enabled_only: Only return enabled rules

        Returns:
            List of CustomRules
        """
        rules = list(RulesEngine._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    @staticmethod
    def evaluate_rule(
        rule: CustomRule, current_value: float
    ) -> CustomRuleResult | None:
        """Evaluate a single rule against a current value.

        Args:
            rule: Rule to evaluate
            current_value: Current metric value

        Returns:
            CustomRuleResult if rule evaluation is complete, None for errors
        """
        if not rule.enabled:
            return None

        triggered = False
        message = ""

        if rule.rule_type == "threshold":
            triggered, message = RulesEngine._evaluate_threshold(
                rule, current_value
            )
        elif rule.rule_type == "trend":
            triggered, message = RulesEngine._evaluate_trend(rule)
        elif rule.rule_type == "anomaly":
            triggered, message = RulesEngine._evaluate_anomaly(
                rule, current_value
            )
        elif rule.rule_type == "composite":
            triggered, message = RulesEngine._evaluate_composite(
                rule, current_value
            )

        if triggered:
            return CustomRuleResult(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                triggered=True,
                severity=rule.severity,
                matched_value=current_value,
                message=message,
            )

        return CustomRuleResult(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            triggered=False,
            severity=rule.severity,
            matched_value=current_value,
            message=f"Rule {rule.name} did not trigger",
        )

    @staticmethod
    def _evaluate_threshold(
        rule: CustomRule, current_value: float
    ) -> tuple[bool, str]:
        """Evaluate threshold-based rule."""
        if rule.operator == ">":
            triggered = current_value > rule.threshold
            op_text = "exceeds"
        elif rule.operator == "<":
            triggered = current_value < rule.threshold
            op_text = "falls below"
        elif rule.operator == "==":
            triggered = abs(current_value - rule.threshold) < 0.01
            op_text = "equals"
        elif rule.operator == "between":
            triggered = (
                rule.threshold <= current_value <= rule.threshold_high
            )
            op_text = f"is between {rule.threshold} and {rule.threshold_high}"
        else:
            return False, "Unknown operator"

        message = (
            f"{rule.name}: Metric {op_text} threshold "
            f"({current_value:.2f} {rule.operator} {rule.threshold})"
        )

        return triggered, message

    @staticmethod
    def _evaluate_trend(rule: CustomRule) -> tuple[bool, str]:
        """Evaluate trend-based rule."""
        if not rule.metric_name:
            return False, "No metric specified for trend rule"

        trend = HistoricalAnalytics.get_metric_trend(rule.metric_name, hours=24)

        if not trend:
            return False, "Insufficient historical data for trend"

        if rule.operator == "trend_change":
            triggered = (
                abs(trend.change_percentage) >= rule.threshold
            )
            message = (
                f"{rule.name}: Metric {trend.trend_direction} "
                f"({trend.change_percentage:.1f}% change)"
            )
        else:
            triggered = trend.trend_direction == rule.threshold  # threshold = direction
            message = (
                f"{rule.name}: Metric is {trend.trend_direction}"
            )

        return triggered, message

    @staticmethod
    def _evaluate_anomaly(
        rule: CustomRule, current_value: float
    ) -> tuple[bool, str]:
        """Evaluate anomaly-based rule."""
        if not rule.metric_name:
            return False, "No metric specified for anomaly rule"

        score = AnomalyDetector.detect_anomaly(
            rule.metric_name, current_value, hours=24
        )

        if not score:
            return False, "Cannot calculate anomaly score"

        # Check severity threshold
        severity_levels = {"high": 3, "medium": 2, "low": 1, "none": 0}
        threshold_severity = severity_levels.get(rule.threshold, 0)
        actual_severity = severity_levels.get(score.severity, 0)

        triggered = actual_severity >= threshold_severity

        message = (
            f"{rule.name}: Detected {score.severity} anomaly "
            f"(z-score: {score.z_score:.2f})"
        )

        return triggered, message

    @staticmethod
    def _evaluate_composite(
        rule: CustomRule, current_value: float
    ) -> tuple[bool, str]:
        """Evaluate composite (multi-condition) rule."""
        # Composite rules can combine multiple conditions
        # For now, simple implementation: check if anomaly AND threshold
        if not rule.metric_name:
            return False, "No metric specified"

        # Check if anomaly
        anomaly_score = AnomalyDetector.detect_anomaly(
            rule.metric_name, current_value, hours=24
        )
        is_anomaly = anomaly_score and anomaly_score.is_anomaly

        # Check if exceeds threshold
        exceeds = current_value > rule.threshold

        triggered = is_anomaly and exceeds

        if triggered:
            message = (
                f"{rule.name}: Anomaly AND threshold breach detected"
            )
        else:
            message = f"{rule.name}: Composite condition not met"

        return triggered, message

    @staticmethod
    def evaluate_all(metrics: dict[str, float]) -> list[CustomRuleResult]:
        """Evaluate all enabled rules against metrics.

        Args:
            metrics: Dictionary of metric_name -> value

        Returns:
            List of triggered CustomRuleResults
        """
        results = []

        for rule in RulesEngine.list_rules(enabled_only=True):
            if not rule.metric_name or rule.metric_name not in metrics:
                continue

            current_value = metrics[rule.metric_name]
            result = RulesEngine.evaluate_rule(rule, current_value)

            if result and result.triggered:
                results.append(result)

        # Sort by severity
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        results.sort(
            key=lambda r: severity_order.get(r.severity, 3)
        )

        return results

    @staticmethod
    def clear_rules() -> None:
        """Clear all rules (for testing)."""
        RulesEngine._rules.clear()

    @staticmethod
    def export_rules() -> list[dict[str, Any]]:
        """Export all rules as JSON-serializable dicts.

        Returns:
            List of rule dictionaries
        """
        result = []
        for rule in RulesEngine._rules.values():
            result.append(rule.model_dump())
        return result

    @staticmethod
    def import_rules(rules_data: list[dict[str, Any]]) -> int:
        """Import rules from JSON-serializable dicts.

        Args:
            rules_data: List of rule dictionaries

        Returns:
            Number of rules imported
        """
        count = 0
        for rule_dict in rules_data:
            try:
                rule = CustomRule(**rule_dict)
                RulesEngine.create_rule(rule)
                count += 1
            except Exception:
                continue

        return count
