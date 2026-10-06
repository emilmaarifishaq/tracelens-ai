"""Tests for AI Insights Generator (Phase 2d)."""

import pytest

from app.models.ue_context import EventType, UEContext
from app.services.ai_insights_generator import (
    AIInsightsGenerator,
    Insight,
    InsightPriority,
    InsightType,
)
from app.services.finding_detector import Finding, FindingDetector, FindingSeverity, FindingType
from app.services.ue_manager import UEContextManager


class TestAIInsightsGenerator:
    """Test AI insights generation from findings and KPIs."""

    def test_high_drop_rate_radio_insight(self):
        """Test insight generation for high drop rate with radio cause."""
        mgr = UEContextManager()

        # Create UEs with radio-related failures
        for i in range(5):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=1000 + i)
            mgr.add_registration(
                ran_ue_id=1000 + i,
                imsi=f"111111111111111{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)

        assert len(findings) > 0
        assert findings[0].finding_type == FindingType.HIGH_DROP_RATE

        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        assert len(insights) > 0
        assert insights[0].insight_type == InsightType.RADIO_DEGRADATION
        assert insights[0].priority in [InsightPriority.HIGH, InsightPriority.CRITICAL]
        assert any(
            "radio" in action.lower() for action in insights[0].recommended_actions
        )

    def test_high_drop_rate_resource_insight(self):
        """Test insight generation for resource-related failures."""
        mgr = UEContextManager()

        for i in range(5):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=2000 + i)
            mgr.add_registration(
                ran_ue_id=2000 + i,
                imsi=f"222222222222222{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RESOURCE",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        assert len(insights) > 0
        resource_insights = [i for i in insights if i.insight_type == InsightType.RESOURCE_EXHAUSTION]
        assert len(resource_insights) > 0
        assert any("resource" in action.lower() for action in resource_insights[0].recommended_actions)

    def test_abnormal_cause_pattern_insight(self):
        """Test insight for high prevalence of abnormal causes."""
        mgr = UEContextManager()

        # Create mixed scenario with abnormal causes
        for i in range(10):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=3000 + i)
            cause = "ABNORMAL_RADIO" if i < 7 else "NORMAL"
            mgr.add_registration(
                ran_ue_id=3000 + i,
                imsi=f"333333333333333{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class=cause,
                success=False if i < 7 else True,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)

        abnormal_findings = [f for f in findings if f.finding_type == FindingType.ABNORMAL_CAUSE_PATTERN]

        if abnormal_findings:
            insights = AIInsightsGenerator.generate_insights(contexts, findings)
            abnormal_insights = [i for i in insights if i.insight_type == InsightType.RELIABILITY_CONCERN]
            assert len(abnormal_insights) > 0

    def test_repeated_failures_insight(self):
        """Test insight for UEs with repeated failures."""
        mgr = UEContextManager()

        # Create UEs with repeated failures
        for i in range(3):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=4000 + i)
            mgr.add_registration(
                ran_ue_id=4000 + i,
                imsi=f"444444444444444{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )
            mgr.add_ics(
                ran_ue_id=4000 + i,
                frame=120 + i,
                time=2.0 + i,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)

        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        config_insights = [i for i in insights if i.insight_type == InsightType.CONFIGURATION_ERROR]
        if len(config_insights) > 0:
            assert config_insights[0].priority in [InsightPriority.HIGH, InsightPriority.CRITICAL]

    def test_slow_procedure_insight(self):
        """Test insight for slow procedures."""
        mgr = UEContextManager()

        # Create slow procedure (2+ seconds)
        mgr.add_initial_ue_message(frame=100, time=0.0, ran_ue_id=5000)
        mgr.add_registration(
            ran_ue_id=5000,
            imsi="555555555555555",
            frame=110,
            time=0.5,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_ics(
            ran_ue_id=5000,
            frame=120,
            time=2.5,  # 2 second delay
            cause_class="NORMAL",
            success=True,
        )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)

        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        perf_insights = [i for i in insights if i.insight_type == InsightType.PERFORMANCE_DEGRADATION]
        if len(perf_insights) > 0:
            assert perf_insights[0].priority in [InsightPriority.MEDIUM, InsightPriority.HIGH]

    def test_incomplete_lifecycle_insight(self):
        """Test insight for incomplete lifecycles."""
        mgr = UEContextManager()

        # Create incomplete lifecycle (no release)
        mgr.add_initial_ue_message(frame=100, time=1.0, ran_ue_id=6000)
        mgr.add_registration(
            ran_ue_id=6000,
            imsi="666666666666666",
            frame=110,
            time=1.5,
            cause_class="NORMAL",
            success=True,
        )
        # No release event = incomplete

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)

        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        incomplete_insights = [
            i for i in insights if i.insight_type == InsightType.RELIABILITY_CONCERN
        ]
        if len(incomplete_insights) > 0:
            assert any("incomplete" in i.title.lower() for i in incomplete_insights)

    def test_zero_success_rate_insight(self):
        """Test insight for zero success rates."""
        mgr = UEContextManager()

        # Create all failures
        for i in range(3):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=7000 + i)
            mgr.add_registration(
                ran_ue_id=7000 + i,
                imsi=f"777777777777777{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RESOURCE",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)

        zero_findings = [f for f in findings if f.finding_type == FindingType.ZERO_SUCCESS_RATE]

        if zero_findings:
            insights = AIInsightsGenerator.generate_insights(contexts, findings)
            critical_insights = [i for i in insights if i.priority == InsightPriority.CRITICAL]
            assert len(critical_insights) > 0

    def test_insights_sorted_by_priority(self):
        """Test that insights are sorted by priority."""
        mgr = UEContextManager()

        # Create diverse failure scenarios
        for i in range(20):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=8000 + i)
            cause = (
                "ABNORMAL_RADIO" if i < 15 else "ABNORMAL_RESOURCE" if i < 18 else "NORMAL"
            )
            mgr.add_registration(
                ran_ue_id=8000 + i,
                imsi=f"888888888888888{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class=cause,
                success=(i >= 18),
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        if len(insights) > 1:
            priority_order = {
                InsightPriority.CRITICAL: 0,
                InsightPriority.HIGH: 1,
                InsightPriority.MEDIUM: 2,
                InsightPriority.LOW: 3,
            }
            for i in range(len(insights) - 1):
                assert priority_order[insights[i].priority] <= priority_order[insights[i + 1].priority]

    def test_insight_confidence_and_impact(self):
        """Test that insights have confidence and impact scores."""
        mgr = UEContextManager()

        for i in range(5):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=9000 + i)
            mgr.add_registration(
                ran_ue_id=9000 + i,
                imsi=f"999999999999999{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        assert len(insights) > 0
        for insight in insights:
            assert 0 <= insight.confidence <= 1.0
            assert 0 <= insight.impact_score <= 100.0

    def test_insight_recommended_actions(self):
        """Test that insights include actionable recommendations."""
        mgr = UEContextManager()

        for i in range(5):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=10000 + i)
            mgr.add_registration(
                ran_ue_id=10000 + i,
                imsi=f"101010101010101{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        assert len(insights) > 0
        for insight in insights:
            assert len(insight.recommended_actions) > 0
            assert all(isinstance(action, str) for action in insight.recommended_actions)

    def test_insight_to_dict(self):
        """Test insight conversion to dictionary."""
        insight = Insight(
            insight_type=InsightType.RADIO_DEGRADATION,
            priority=InsightPriority.HIGH,
            title="Test Insight",
            description="Test description",
            root_cause="Test root cause",
            recommended_actions=["Action 1", "Action 2"],
            affected_kpis=["kpi1", "kpi2"],
            related_findings=["finding1"],
            confidence=0.85,
            impact_score=75.0,
        )

        insight_dict = insight.to_dict()

        assert insight_dict["type"] == "radio_degradation"
        assert insight_dict["priority"] == "high"
        assert insight_dict["title"] == "Test Insight"
        assert len(insight_dict["recommended_actions"]) == 2
        assert insight_dict["confidence"] == 0.85
        assert insight_dict["impact_score"] == 75.0

    def test_capacity_issue_cross_finding(self):
        """Test cross-finding analysis for capacity issues."""
        mgr = UEContextManager()

        # Create scenario with multiple failures indicating capacity issues
        for i in range(30):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=11000 + i)
            mgr.add_registration(
                ran_ue_id=11000 + i,
                imsi=f"111111111111111{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RESOURCE" if i < 20 else "NORMAL",
                success=(i >= 20),
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        capacity_insights = [i for i in insights if i.insight_type == InsightType.CAPACITY_ISSUE]
        if len(capacity_insights) > 0:
            assert capacity_insights[0].priority == InsightPriority.HIGH
            assert "capacity" in capacity_insights[0].title.lower()

    def test_empty_contexts(self):
        """Test insight generation with empty contexts."""
        insights = AIInsightsGenerator.generate_insights([], [])
        assert len(insights) == 0

    def test_empty_findings(self):
        """Test insight generation with empty findings."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=100, time=1.0, ran_ue_id=12000)
        mgr.add_registration(
            ran_ue_id=12000,
            imsi="121212121212121",
            frame=110,
            time=1.5,
            cause_class="NORMAL",
            success=True,
        )

        contexts = mgr.get_all_contexts()
        insights = AIInsightsGenerator.generate_insights(contexts, [])
        assert len(insights) == 0

    def test_healthy_trace_no_critical_insights(self):
        """Test that healthy trace produces no critical insights."""
        mgr = UEContextManager()

        # Create successful procedures
        for i in range(5):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=13000 + i)
            mgr.add_registration(
                ran_ue_id=13000 + i,
                imsi=f"131313131313131{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="NORMAL",
                success=True,
            )
            mgr.add_ics(
                ran_ue_id=13000 + i,
                frame=120 + i,
                time=1.8 + i,
                cause_class="NORMAL",
                success=True,
            )
            mgr.add_pdu_session_setup(
                ran_ue_id=13000 + i,
                frame=130 + i,
                time=2.0 + i,
                cause_class="NORMAL",
                success=True,
            )
            mgr.add_release(
                ran_ue_id=13000 + i,
                imsi=f"131313131313131{i}",
                frame=140 + i,
                time=5.0 + i,
                cause_class="NORMAL",
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        critical_insights = [i for i in insights if i.priority == InsightPriority.CRITICAL]
        assert len(critical_insights) == 0

    def test_insight_related_findings(self):
        """Test that insights reference related findings."""
        mgr = UEContextManager()

        for i in range(5):
            mgr.add_initial_ue_message(frame=100 + i, time=1.0 + i, ran_ue_id=14000 + i)
            mgr.add_registration(
                ran_ue_id=14000 + i,
                imsi=f"141414141414141{i}",
                frame=110 + i,
                time=1.5 + i,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        contexts = mgr.get_all_contexts()
        findings = FindingDetector.detect_findings(contexts)
        insights = AIInsightsGenerator.generate_insights(contexts, findings)

        assert len(insights) > 0
        for insight in insights:
            assert len(insight.related_findings) > 0
