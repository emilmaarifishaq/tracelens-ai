"""Finding detection from UE lifecycle analysis.

Detects anomalies, patterns, and issues in 5G trace data with severity scoring
and actionable insights.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.models.ue_context import UEContext, EventType
from app.services.kpi_calculator import KPICalculator


class FindingSeverity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"  # Network outage or critical failures
    WARNING = "WARNING"  # Significant issues affecting service quality
    INFO = "INFO"  # Informational findings worth noting


class FindingType(str, Enum):
    """Types of findings that can be detected."""

    HIGH_DROP_RATE = "high_drop_rate"
    ABNORMAL_CAUSE_PATTERN = "abnormal_cause_pattern"
    REPEATED_FAILURES = "repeated_failures"
    SLOW_PROCEDURE = "slow_procedure"
    INCOMPLETE_LIFECYCLE = "incomplete_lifecycle"
    ZERO_SUCCESS_RATE = "zero_success_rate"
    REGISTRATION_FAILURES = "registration_failures"
    ICS_FAILURES = "ics_failures"
    PDU_FAILURES = "pdu_failures"


@dataclass
class Finding:
    """Represents a detected finding or anomaly.

    A finding captures a specific issue detected in the trace with context,
    severity, and recommended actions.
    """

    finding_type: FindingType
    severity: FindingSeverity
    title: str
    description: str
    affected_ues: int = 0
    metric_value: float = 0.0
    cause_class: str | None = None
    procedure: str | None = None  # "registration", "ics", "pdu_session"
    score: float = 0.0  # Severity score 0-100
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_ues": self.affected_ues,
            "metric_value": self.metric_value,
            "cause_class": self.cause_class,
            "procedure": self.procedure,
            "score": self.score,
            "details": self.details,
        }


class FindingDetector:
    """Detects findings and anomalies in UE contexts.

    Analyzes lifecycle data to identify patterns, failures, and performance issues
    with severity scoring based on impact and prevalence.
    """

    # Thresholds for various findings
    HIGH_DROP_RATE_THRESHOLD = 20.0  # 20% drop rate
    LOW_SUCCESS_RATE_THRESHOLD = 80.0  # Below 80% is concerning
    SLOW_PROCEDURE_THRESHOLD = 1.0  # 1 second is slow
    ABNORMAL_CAUSE_THRESHOLD = 30.0  # 30% of events with abnormal cause

    @staticmethod
    def detect_findings(contexts: list[UEContext]) -> list[Finding]:
        """Detect all findings in the given contexts.

        Args:
            contexts: List of UE contexts to analyze

        Returns:
            List of Finding objects sorted by severity score
        """
        if not contexts:
            return []

        findings: list[Finding] = []

        # Detect high drop rates
        findings.extend(FindingDetector._detect_high_drop_rates(contexts))

        # Detect abnormal cause patterns
        findings.extend(FindingDetector._detect_abnormal_cause_patterns(contexts))

        # Detect repeated failures
        findings.extend(FindingDetector._detect_repeated_failures(contexts))

        # Detect slow procedures
        findings.extend(FindingDetector._detect_slow_procedures(contexts))

        # Detect incomplete lifecycles
        findings.extend(FindingDetector._detect_incomplete_lifecycles(contexts))

        # Detect zero success rates by procedure
        findings.extend(FindingDetector._detect_zero_success_rates(contexts))

        # Sort by score (descending)
        findings.sort(key=lambda f: f.score, reverse=True)

        return findings

    @staticmethod
    def _detect_high_drop_rates(contexts: list[UEContext]) -> list[Finding]:
        """Detect procedures with high drop rates."""
        findings: list[Finding] = []
        drop_rates = KPICalculator.drop_rate_by_cause(contexts)

        for cause_class, drop_rate in drop_rates.items():
            if drop_rate >= FindingDetector.HIGH_DROP_RATE_THRESHOLD:
                severity = (
                    FindingSeverity.CRITICAL
                    if drop_rate >= 50.0
                    else FindingSeverity.WARNING
                )
                score = min(100.0, drop_rate)

                affected = sum(
                    1
                    for ctx in contexts
                    for event in ctx.events
                    if event.get("cause_class") == cause_class
                    and event.get("success") is False
                )

                findings.append(
                    Finding(
                        finding_type=FindingType.HIGH_DROP_RATE,
                        severity=severity,
                        title=f"High drop rate for {cause_class}",
                        description=f"{drop_rate:.1f}% of {cause_class} events resulted in failures",
                        affected_ues=affected,
                        metric_value=drop_rate,
                        cause_class=cause_class,
                        score=score,
                        details={"drop_rate": drop_rate},
                    )
                )

        return findings

    @staticmethod
    def _detect_abnormal_cause_patterns(contexts: list[UEContext]) -> list[Finding]:
        """Detect patterns of abnormal causes."""
        findings: list[Finding] = []

        abnormal_causes = [
            cause
            for cause in [
                "ABNORMAL_RADIO",
                "ABNORMAL_RESOURCE",
                "ABNORMAL_TRANSPORT",
                "ABNORMAL_PROTOCOL",
                "ABNORMAL_CONFIG",
            ]
        ]

        abnormal_count = 0
        total_count = 0

        for ctx in contexts:
            for event in ctx.events:
                cause = event.get("cause_class")
                if cause:
                    total_count += 1
                    if cause in abnormal_causes:
                        abnormal_count += 1

        if total_count > 0:
            abnormal_rate = (abnormal_count / total_count) * 100
            if abnormal_rate >= FindingDetector.ABNORMAL_CAUSE_THRESHOLD:
                severity = (
                    FindingSeverity.CRITICAL
                    if abnormal_rate >= 50.0
                    else FindingSeverity.WARNING
                )
                score = min(100.0, abnormal_rate)

                findings.append(
                    Finding(
                        finding_type=FindingType.ABNORMAL_CAUSE_PATTERN,
                        severity=severity,
                        title="High prevalence of abnormal causes",
                        description=f"{abnormal_rate:.1f}% of lifecycle events classified as abnormal",
                        affected_ues=len(contexts),
                        metric_value=abnormal_rate,
                        score=score,
                        details={
                            "abnormal_count": abnormal_count,
                            "total_count": total_count,
                        },
                    )
                )

        return findings

    @staticmethod
    def _detect_repeated_failures(contexts: list[UEContext]) -> list[Finding]:
        """Detect UEs with repeated procedure failures."""
        findings: list[Finding] = []
        ues_with_failures: dict[str, int] = {}

        for ctx in contexts:
            failure_count = ctx.failed_event_count()
            if failure_count >= 2:  # 2 or more failures
                key = f"imsi_{ctx.imsi}" if ctx.imsi else f"ran_ue_{ctx.ran_ue_id}"
                ues_with_failures[key] = failure_count

        if ues_with_failures:
            affected = len(ues_with_failures)
            avg_failures = sum(ues_with_failures.values()) / len(ues_with_failures)

            severity = (
                FindingSeverity.WARNING
                if affected >= len(contexts) * 0.1
                else FindingSeverity.INFO
            )
            score = min(100.0, avg_failures * 10)

            findings.append(
                Finding(
                    finding_type=FindingType.REPEATED_FAILURES,
                    severity=severity,
                    title="UEs with repeated procedure failures",
                    description=f"{affected} UEs experienced {avg_failures:.1f} failures on average",
                    affected_ues=affected,
                    metric_value=avg_failures,
                    score=score,
                    details={"ues_affected": affected},
                )
            )

        return findings

    @staticmethod
    def _detect_slow_procedures(contexts: list[UEContext]) -> list[Finding]:
        """Detect procedures that are unusually slow."""
        findings: list[Finding] = []
        timings = KPICalculator.procedure_timing(contexts)

        procedure_names = {
            "registration": "Registration",
            "ics": "ICS",
            "pdu_session": "PDU Session",
            "total": "Total Lifetime",
        }

        for proc_key, proc_name in procedure_names.items():
            if proc_key in timings and timings[proc_key]:
                timing = timings[proc_key]
                avg_time = timing.get("avg", 0.0)

                if avg_time > FindingDetector.SLOW_PROCEDURE_THRESHOLD:
                    severity = (
                        FindingSeverity.WARNING
                        if avg_time > 2.0
                        else FindingSeverity.INFO
                    )
                    score = min(100.0, (avg_time / 5.0) * 100)

                    findings.append(
                        Finding(
                            finding_type=FindingType.SLOW_PROCEDURE,
                            severity=severity,
                            title=f"Slow {proc_name} procedure",
                            description=f"Average {proc_name.lower()} time: {avg_time:.2f}s",
                            metric_value=avg_time,
                            procedure=proc_key,
                            score=score,
                            details={
                                "min": timing.get("min", 0.0),
                                "max": timing.get("max", 0.0),
                                "median": timing.get("median", 0.0),
                            },
                        )
                    )

        return findings

    @staticmethod
    def _detect_incomplete_lifecycles(contexts: list[UEContext]) -> list[Finding]:
        """Detect UEs with incomplete lifecycles."""
        findings: list[Finding] = []

        incomplete_count = sum(1 for ctx in contexts if not ctx.is_complete())

        if incomplete_count > 0:
            incomplete_rate = (incomplete_count / len(contexts)) * 100
            severity = (
                FindingSeverity.CRITICAL
                if incomplete_rate >= 50.0
                else FindingSeverity.WARNING
                if incomplete_rate >= 20.0
                else FindingSeverity.INFO
            )
            score = min(100.0, incomplete_rate)

            findings.append(
                Finding(
                    finding_type=FindingType.INCOMPLETE_LIFECYCLE,
                    severity=severity,
                    title="Incomplete UE lifecycles detected",
                    description=f"{incomplete_rate:.1f}% of UEs ({incomplete_count}/{len(contexts)}) have incomplete lifecycles",
                    affected_ues=incomplete_count,
                    metric_value=incomplete_rate,
                    score=score,
                    details={"incomplete_count": incomplete_count},
                )
            )

        return findings

    @staticmethod
    def _detect_zero_success_rates(contexts: list[UEContext]) -> list[Finding]:
        """Detect procedures with 0% success rate."""
        findings: list[Finding] = []

        reg_rate = KPICalculator.registration_success_rate(contexts)
        ics_rate = KPICalculator.ics_success_rate(contexts)
        pdu_rate = KPICalculator.pdu_session_success_rate(contexts)

        if reg_rate == 0.0 and sum(
            1
            for ctx in contexts
            for event in ctx.events
            if event["type"] == EventType.REGISTRATION_ATTEMPT
        ):
            findings.append(
                Finding(
                    finding_type=FindingType.ZERO_SUCCESS_RATE,
                    severity=FindingSeverity.CRITICAL,
                    title="Registration success rate is 0%",
                    description="All registration attempts failed",
                    metric_value=0.0,
                    procedure="registration",
                    score=100.0,
                )
            )

        if ics_rate == 0.0 and sum(
            1
            for ctx in contexts
            for event in ctx.events
            if event["type"] == EventType.ICS_ATTEMPT
        ):
            findings.append(
                Finding(
                    finding_type=FindingType.ZERO_SUCCESS_RATE,
                    severity=FindingSeverity.CRITICAL,
                    title="ICS success rate is 0%",
                    description="All ICS attempts failed",
                    metric_value=0.0,
                    procedure="ics",
                    score=100.0,
                )
            )

        if pdu_rate == 0.0 and sum(
            1
            for ctx in contexts
            for event in ctx.events
            if event["type"] == EventType.PDU_SESSION_SETUP
        ):
            findings.append(
                Finding(
                    finding_type=FindingType.ZERO_SUCCESS_RATE,
                    severity=FindingSeverity.WARNING,
                    title="PDU Session success rate is 0%",
                    description="All PDU session setup attempts failed",
                    metric_value=0.0,
                    procedure="pdu_session",
                    score=80.0,
                )
            )

        return findings
