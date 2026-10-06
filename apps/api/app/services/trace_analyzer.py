"""Complete trace analysis pipeline integrating all phases.

Coordinates Phase 1b-2d to provide comprehensive 5G trace analysis:
- Phase 1b: Cause Classification
- Phase 2a: UE Context Tracking
- Phase 2b: KPI Calculation
- Phase 2c: Finding Detection
- Phase 2d: AI Insights Generation
"""

from app.models.trace import FindingModel, InsightModel, KPIMetrics, TraceAnalysis
from app.models.ue_context import UEContext
from app.services.ai_insights_generator import AIInsightsGenerator, Insight
from app.services.finding_detector import Finding, FindingDetector
from app.services.kpi_calculator import KPICalculator


class TraceAnalyzer:
    """Orchestrates complete trace analysis pipeline."""

    @staticmethod
    def analyze(ue_contexts: list[UEContext]) -> TraceAnalysis:
        """Run complete analysis on UE contexts.

        Executes all phases (2b-2d) to generate comprehensive trace analysis:
        - KPI metrics (Phase 2b)
        - Findings/anomalies (Phase 2c)
        - AI insights (Phase 2d)

        Args:
            ue_contexts: List of UE lifecycle contexts from Phase 2a

        Returns:
            TraceAnalysis with metrics, findings, and insights
        """
        analysis = TraceAnalysis()

        if not ue_contexts:
            return analysis

        # Phase 2b: Calculate KPIs
        kpi_dict = KPICalculator.summary_stats(ue_contexts)
        analysis.kpi_metrics = KPIMetrics(**kpi_dict)

        # Phase 2c: Detect findings
        findings: list[Finding] = FindingDetector.detect_findings(ue_contexts)
        analysis.findings = [
            FindingModel(
                finding_type=f.finding_type.value,
                severity=f.severity.value,
                title=f.title,
                description=f.description,
                affected_ues=f.affected_ues,
                metric_value=f.metric_value,
                cause_class=f.cause_class,
                procedure=f.procedure,
                score=f.score,
                details=f.details,
            )
            for f in findings
        ]

        # Phase 2d: Generate AI insights
        insights: list[Insight] = AIInsightsGenerator.generate_insights(
            ue_contexts, findings
        )
        analysis.insights = [
            InsightModel(
                insight_type=i.insight_type.value,
                priority=i.priority.value,
                title=i.title,
                description=i.description,
                root_cause=i.root_cause,
                recommended_actions=i.recommended_actions,
                affected_kpis=i.affected_kpis,
                related_findings=i.related_findings,
                confidence=i.confidence,
                impact_score=i.impact_score,
                details=i.details,
            )
            for i in insights
        ]

        return analysis
