"""AI insights generation from findings and KPI analysis.

Generates actionable recommendations and insights from detected findings,
KPI metrics, and UE lifecycle patterns.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.models.ue_context import UEContext
from app.services.finding_detector import Finding, FindingDetector, FindingSeverity
from app.services.kpi_calculator import KPICalculator


class InsightType(str, Enum):
    """Types of AI-generated insights."""

    NETWORK_CONGESTION = "network_congestion"
    RADIO_DEGRADATION = "radio_degradation"
    CAPACITY_ISSUE = "capacity_issue"
    CONFIGURATION_ERROR = "configuration_error"
    RELIABILITY_CONCERN = "reliability_concern"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SIGNALING_ISSUE = "signaling_issue"
    SECURITY_CONCERN = "security_concern"
    TREND_ALERT = "trend_alert"


class InsightPriority(str, Enum):
    """Priority levels for insights."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Insight:
    """Represents an AI-generated insight or recommendation.

    Insights are derived from findings and KPI analysis, providing
    actionable recommendations and root cause analysis.
    """

    insight_type: InsightType
    priority: InsightPriority
    title: str
    description: str
    root_cause: str | None = None
    recommended_actions: list[str] = field(default_factory=list)
    affected_kpis: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0-1 confidence level
    impact_score: float = 0.0  # 0-100 impact rating
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert insight to dictionary."""
        return {
            "type": self.insight_type.value,
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "root_cause": self.root_cause,
            "recommended_actions": self.recommended_actions,
            "affected_kpis": self.affected_kpis,
            "related_findings": self.related_findings,
            "confidence": self.confidence,
            "impact_score": self.impact_score,
            "details": self.details,
        }


class AIInsightsGenerator:
    """Generates AI insights from findings and KPI metrics.

    Analyzes trace data findings and KPI metrics to identify root causes,
    assess impacts, and provide actionable recommendations.
    """

    @staticmethod
    def generate_insights(
        contexts: list[UEContext], findings: list[Finding]
    ) -> list[Insight]:
        """Generate insights from UE contexts and detected findings.

        Args:
            contexts: List of UE contexts
            findings: List of detected findings from Phase 2c

        Returns:
            List of Insight objects sorted by priority and impact
        """
        if not contexts or not findings:
            return []

        insights: list[Insight] = []

        # Analyze each finding and generate related insights
        for finding in findings:
            if finding.finding_type.value == "high_drop_rate":
                insights.extend(
                    AIInsightsGenerator._analyze_high_drop_rate(contexts, finding)
                )
            elif finding.finding_type.value == "abnormal_cause_pattern":
                insights.extend(
                    AIInsightsGenerator._analyze_abnormal_causes(contexts, finding)
                )
            elif finding.finding_type.value == "repeated_failures":
                insights.extend(
                    AIInsightsGenerator._analyze_repeated_failures(contexts, finding)
                )
            elif finding.finding_type.value == "slow_procedure":
                insights.extend(
                    AIInsightsGenerator._analyze_slow_procedure(contexts, finding)
                )
            elif finding.finding_type.value == "incomplete_lifecycle":
                insights.extend(
                    AIInsightsGenerator._analyze_incomplete_lifecycle(
                        contexts, finding
                    )
                )
            elif finding.finding_type.value == "zero_success_rate":
                insights.extend(
                    AIInsightsGenerator._analyze_zero_success_rate(contexts, finding)
                )

        # Generate cross-finding insights
        if findings:
            insights.extend(AIInsightsGenerator._analyze_patterns(contexts, findings))

        # Sort by priority and impact
        priority_order = {
            InsightPriority.CRITICAL: 0,
            InsightPriority.HIGH: 1,
            InsightPriority.MEDIUM: 2,
            InsightPriority.LOW: 3,
        }
        insights.sort(
            key=lambda i: (priority_order[i.priority], -i.impact_score),
            reverse=False,
        )

        return insights

    @staticmethod
    def _analyze_high_drop_rate(contexts: list[UEContext], finding: Finding) -> list[Insight]:
        """Analyze high drop rate findings."""
        insights: list[Insight] = []

        cause = finding.cause_class or "unknown"
        drop_rate = finding.metric_value

        if drop_rate >= 50:
            priority = InsightPriority.CRITICAL
            confidence = 0.95
        elif drop_rate >= 20:
            priority = InsightPriority.HIGH
            confidence = 0.90
        else:
            priority = InsightPriority.MEDIUM
            confidence = 0.85

        # Determine root cause based on cause class
        if "RADIO" in cause:
            root_cause = "Radio resource degradation or UE mobility issues"
            insight_type = InsightType.RADIO_DEGRADATION
            actions = [
                "Check radio signal quality and interference levels",
                "Verify UE antenna performance and antenna selection",
                "Review handover parameters and mobility optimization",
                "Assess radio resource allocation and congestion",
            ]
        elif "RESOURCE" in cause:
            root_cause = "Network resource exhaustion or allocation failures"
            insight_type = InsightType.RESOURCE_EXHAUSTION
            actions = [
                "Monitor network resource utilization trends",
                "Optimize resource allocation policies",
                "Consider capacity expansion or load balancing",
                "Review admission control thresholds",
            ]
        elif "TRANSPORT" in cause:
            root_cause = "Transport layer connectivity or performance issues"
            insight_type = InsightType.NETWORK_CONGESTION
            actions = [
                "Check backhaul and network interface status",
                "Monitor packet loss and latency",
                "Verify network routing and failover mechanisms",
                "Assess transport layer load balancing",
            ]
        elif "PROTOCOL" in cause:
            root_cause = "Protocol implementation or signaling issues"
            insight_type = InsightType.SIGNALING_ISSUE
            actions = [
                "Review protocol implementation and state machines",
                "Check timer configurations and retransmission settings",
                "Verify compatibility with peer network elements",
                "Analyze message flows and error conditions",
            ]
        else:
            root_cause = f"Issues related to {cause.lower()} procedures"
            insight_type = InsightType.RELIABILITY_CONCERN
            actions = [
                f"Investigate {cause.lower()} procedure failures",
                "Analyze error logs and event correlations",
                "Review procedure configuration and thresholds",
                "Implement targeted monitoring and alerting",
            ]

        insights.append(
            Insight(
                insight_type=insight_type,
                priority=priority,
                title=f"High failure rate in {cause}",
                description=f"{drop_rate:.1f}% of {cause} procedures are failing. "
                f"This affects {finding.affected_ues} UEs and indicates significant service degradation.",
                root_cause=root_cause,
                recommended_actions=actions,
                affected_kpis=["completion_rate", "success_rate_by_cause"],
                related_findings=[finding.finding_type.value],
                confidence=confidence,
                impact_score=min(100.0, drop_rate),
                details={"cause_class": cause, "drop_rate": drop_rate},
            )
        )

        return insights

    @staticmethod
    def _analyze_abnormal_causes(contexts: list[UEContext], finding: Finding) -> list[Insight]:
        """Analyze abnormal cause pattern findings."""
        insights: list[Insight] = []

        abnormal_rate = finding.metric_value

        if abnormal_rate >= 50:
            priority = InsightPriority.CRITICAL
            confidence = 0.95
        elif abnormal_rate >= 30:
            priority = InsightPriority.HIGH
            confidence = 0.90
        else:
            priority = InsightPriority.MEDIUM
            confidence = 0.80

        root_cause = (
            "Systemic network or radio conditions causing abnormal failures across multiple procedures"
        )

        insights.append(
            Insight(
                insight_type=InsightType.RELIABILITY_CONCERN,
                priority=priority,
                title="High prevalence of abnormal failure causes",
                description=f"{abnormal_rate:.1f}% of events are failing with abnormal causes. "
                f"This indicates underlying network degradation or resource constraints.",
                root_cause=root_cause,
                recommended_actions=[
                    "Conduct comprehensive network health assessment",
                    "Monitor radio environment and interference levels",
                    "Check for resource exhaustion or overload conditions",
                    "Review recent network changes or maintenance activities",
                    "Analyze time correlation with events like peak hours or updates",
                ],
                affected_kpis=["registration_success_rate", "ics_success_rate", "pdu_session_success_rate"],
                related_findings=[finding.finding_type.value],
                confidence=confidence,
                impact_score=abnormal_rate,
                details={"abnormal_rate": abnormal_rate},
            )
        )

        return insights

    @staticmethod
    def _analyze_repeated_failures(contexts: list[UEContext], finding: Finding) -> list[Insight]:
        """Analyze repeated failures findings."""
        insights: list[Insight] = []

        affected = finding.affected_ues
        avg_failures = finding.metric_value

        if affected >= len(contexts) * 0.5:
            priority = InsightPriority.CRITICAL
            confidence = 0.92
        elif affected >= len(contexts) * 0.2:
            priority = InsightPriority.HIGH
            confidence = 0.88
        else:
            priority = InsightPriority.MEDIUM
            confidence = 0.80

        root_cause = (
            "Specific UEs experiencing persistent issues due to configuration, "
            "capability mismatch, or device-specific problems"
        )

        insights.append(
            Insight(
                insight_type=InsightType.CONFIGURATION_ERROR,
                priority=priority,
                title="Multiple UEs with repeated procedure failures",
                description=f"{affected} UEs ({affected/len(contexts)*100:.1f}%) are experiencing repeated failures. "
                f"Each affected UE has an average of {avg_failures:.1f} failures.",
                root_cause=root_cause,
                recommended_actions=[
                    "Identify common characteristics of affected UEs (model, vendor, firmware)",
                    "Review UE-specific configurations or whitelisting",
                    "Verify capability negotiation and feature support",
                    "Check for known device issues or compatibility problems",
                    "Consider targeted device firmware updates or workarounds",
                ],
                affected_kpis=["completion_rate"],
                related_findings=[finding.finding_type.value],
                confidence=confidence,
                impact_score=min(100.0, affected / len(contexts) * 100),
                details={"affected_ues": affected, "avg_failures": avg_failures},
            )
        )

        return insights

    @staticmethod
    def _analyze_slow_procedure(contexts: list[UEContext], finding: Finding) -> list[Insight]:
        """Analyze slow procedure findings."""
        insights: list[Insight] = []

        procedure = finding.procedure or "unknown"
        avg_time = finding.metric_value

        if avg_time > 2.0:
            priority = InsightPriority.HIGH
            confidence = 0.90
        else:
            priority = InsightPriority.MEDIUM
            confidence = 0.85

        root_cause = (
            f"Delays in {procedure} procedure due to network load, "
            "signaling processing, or resource allocation contention"
        )

        insights.append(
            Insight(
                insight_type=InsightType.PERFORMANCE_DEGRADATION,
                priority=priority,
                title=f"Slow {procedure.upper()} procedure performance",
                description=f"Average {procedure} time is {avg_time:.2f}s, "
                f"exceeding the 1.0s threshold. This impacts user experience and network efficiency.",
                root_cause=root_cause,
                recommended_actions=[
                    "Analyze signaling flow and identify bottlenecks",
                    "Monitor network element processing times",
                    "Optimize timer and retry settings",
                    "Check for resource contention or congestion",
                    "Review latency between network components",
                    "Consider load balancing or scaling improvements",
                ],
                affected_kpis=["procedure_timing"],
                related_findings=[finding.finding_type.value],
                confidence=confidence,
                impact_score=min(100.0, (avg_time / 5.0) * 100),
                details={"procedure": procedure, "avg_time": avg_time},
            )
        )

        return insights

    @staticmethod
    def _analyze_incomplete_lifecycle(contexts: list[UEContext], finding: Finding) -> list[Insight]:
        """Analyze incomplete lifecycle findings."""
        insights: list[Insight] = []

        incomplete_rate = finding.metric_value

        if incomplete_rate >= 50:
            priority = InsightPriority.CRITICAL
            confidence = 0.95
        elif incomplete_rate >= 20:
            priority = InsightPriority.HIGH
            confidence = 0.90
        else:
            priority = InsightPriority.MEDIUM
            confidence = 0.85

        root_cause = (
            "UEs not completing full lifecycle (missing start or end events), "
            "indicating early disconnections, crashes, or trace capture issues"
        )

        insights.append(
            Insight(
                insight_type=InsightType.RELIABILITY_CONCERN,
                priority=priority,
                title="Incomplete UE lifecycles detected",
                description=f"{incomplete_rate:.1f}% of UEs have incomplete lifecycles. "
                f"This may indicate unexpected disconnections or service interruptions.",
                root_cause=root_cause,
                recommended_actions=[
                    "Verify trace capture completeness and duration",
                    "Check for early session terminations or abnormal releases",
                    "Analyze release cause codes and error conditions",
                    "Review UE attachment and detachment patterns",
                    "Investigate network-initiated disconnections",
                    "Verify billing/CDR record completeness",
                ],
                affected_kpis=["completion_rate"],
                related_findings=[finding.finding_type.value],
                confidence=confidence,
                impact_score=incomplete_rate,
                details={"incomplete_rate": incomplete_rate},
            )
        )

        return insights

    @staticmethod
    def _analyze_zero_success_rate(contexts: list[UEContext], finding: Finding) -> list[Insight]:
        """Analyze zero success rate findings."""
        insights: list[Insight] = []

        procedure = finding.procedure or "unknown"

        insights.append(
            Insight(
                insight_type=InsightType.SIGNALING_ISSUE,
                priority=InsightPriority.CRITICAL,
                title=f"Complete {procedure.upper()} procedure failure",
                description=f"0% of {procedure} procedures succeeded. "
                f"This is a critical service outage affecting all UEs.",
                root_cause=f"Complete failure of {procedure} procedure infrastructure, "
                f"typically due to network element unavailability or misconfiguration",
                recommended_actions=[
                    f"Immediately verify {procedure} service availability",
                    "Check network element health and connectivity",
                    "Review recent configuration changes",
                    "Inspect signaling messages for error patterns",
                    "Verify peer network element functionality",
                    "Activate fallback or redundancy mechanisms if available",
                ],
                affected_kpis=[f"{procedure}_success_rate"],
                related_findings=[finding.finding_type.value],
                confidence=0.98,
                impact_score=100.0,
                details={"procedure": procedure},
            )
        )

        return insights

    @staticmethod
    def _analyze_patterns(contexts: list[UEContext], findings: list[Finding]) -> list[Insight]:
        """Analyze cross-finding patterns and correlations."""
        insights: list[Insight] = []

        if not findings:
            return insights

        kpis = KPICalculator.summary_stats(contexts)

        # Check for capacity issues
        completion_rate = kpis.get("completion_rate", 0.0)
        if completion_rate < 50 and len(findings) >= 3:
            insights.append(
                Insight(
                    insight_type=InsightType.CAPACITY_ISSUE,
                    priority=InsightPriority.HIGH,
                    title="Multiple failure indicators suggest capacity issues",
                    description="Multiple findings combined with low completion rate suggest network is operating near or over capacity.",
                    root_cause="Network resources (spectrum, processing, backhaul) are exhausted or over-provisioned",
                    recommended_actions=[
                        "Conduct capacity planning assessment",
                        "Analyze peak hour utilization trends",
                        "Consider load balancing or traffic steering",
                        "Evaluate spectrum efficiency optimizations",
                        "Plan infrastructure expansion or upgrades",
                    ],
                    affected_kpis=["completion_rate", "registration_success_rate", "ics_success_rate"],
                    related_findings=[f.finding_type.value for f in findings[:3]],
                    confidence=0.85,
                    impact_score=75.0,
                    details={"findings_count": len(findings), "completion_rate": completion_rate},
                )
            )

        # Check for systematic issues across all procedures
        reg_rate = kpis.get("registration_success_rate", 0.0)
        ics_rate = kpis.get("ics_success_rate", 0.0)
        pdu_rate = kpis.get("pdu_session_success_rate", 0.0)

        if reg_rate < 50 and ics_rate < 50 and pdu_rate < 50:
            insights.append(
                Insight(
                    insight_type=InsightType.NETWORK_CONGESTION,
                    priority=InsightPriority.CRITICAL,
                    title="Systemic network failure across all procedures",
                    description="All major procedures (registration, ICS, PDU) are failing at >50%. "
                    "This indicates a network-wide outage or severe degradation.",
                    root_cause="Network-wide issue such as core outage, routing failure, or catastrophic resource exhaustion",
                    recommended_actions=[
                        "Declare network incident and activate incident response",
                        "Check core network element status and connectivity",
                        "Verify routing and BGP convergence",
                        "Inspect for DDoS attacks or malicious traffic",
                        "Review recent infrastructure changes",
                        "Activate redundancy and failover mechanisms",
                    ],
                    affected_kpis=["registration_success_rate", "ics_success_rate", "pdu_session_success_rate"],
                    related_findings=[f.finding_type.value for f in findings],
                    confidence=0.96,
                    impact_score=100.0,
                    details={"reg_rate": reg_rate, "ics_rate": ics_rate, "pdu_rate": pdu_rate},
                )
            )

        return insights
