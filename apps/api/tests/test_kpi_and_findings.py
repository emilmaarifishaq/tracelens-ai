"""Phase 2b and 2c: KPI calculation and finding detection tests."""

import pytest
from app.models.ue_context import UEContext, EventType
from app.services.kpi_calculator import KPICalculator
from app.services.finding_detector import (
    FindingDetector,
    FindingSeverity,
    FindingType,
)
from app.services.ue_manager import UEContextManager


class TestKPICalculator:
    """Test KPI calculation functionality."""

    def test_registration_success_rate_all_success(self):
        """Test registration success rate when all succeed."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_initial_ue_message(frame=3, time=0.2, ran_ue_id=2)
        mgr.add_registration(
            ran_ue_id=2,
            imsi="223456789012345",
            frame=4,
            time=0.3,
            cause_class="NORMAL",
            success=True,
        )

        rate = KPICalculator.registration_success_rate(mgr.get_all_contexts())
        assert rate == 100.0

    def test_registration_success_rate_mixed(self):
        """Test registration success rate with mixed results."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_initial_ue_message(frame=3, time=0.2, ran_ue_id=2)
        mgr.add_registration(
            ran_ue_id=2,
            imsi="223456789012345",
            frame=4,
            time=0.3,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )

        rate = KPICalculator.registration_success_rate(mgr.get_all_contexts())
        assert rate == 50.0

    def test_registration_success_rate_filtered_by_cause(self):
        """Test registration success rate filtered by cause class."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_initial_ue_message(frame=3, time=0.2, ran_ue_id=2)
        mgr.add_registration(
            ran_ue_id=2,
            imsi="223456789012345",
            frame=4,
            time=0.3,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )

        normal_rate = KPICalculator.registration_success_rate(
            mgr.get_all_contexts(), cause_class="NORMAL"
        )
        assert normal_rate == 100.0

        abnormal_rate = KPICalculator.registration_success_rate(
            mgr.get_all_contexts(), cause_class="ABNORMAL_RADIO"
        )
        assert abnormal_rate == 0.0

    def test_ics_success_rate(self):
        """Test ICS success rate calculation."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_ics(ran_ue_id=1, frame=2, time=0.1, cause_class="NORMAL", success=True)
        mgr.add_initial_ue_message(frame=3, time=0.15, ran_ue_id=2)
        mgr.add_ics(
            ran_ue_id=2, frame=4, time=0.2, cause_class="ABNORMAL_RADIO", success=False
        )
        mgr.add_initial_ue_message(frame=5, time=0.25, ran_ue_id=3)
        mgr.add_ics(ran_ue_id=3, frame=6, time=0.3, cause_class="NORMAL", success=True)

        rate = KPICalculator.ics_success_rate(mgr.get_all_contexts())
        assert rate == pytest.approx(66.67, rel=0.01)

    def test_pdu_session_success_rate(self):
        """Test PDU session success rate calculation."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_pdu_session_setup(
            ran_ue_id=1,
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
            pdu_session_id=1,
        )
        mgr.add_initial_ue_message(frame=3, time=0.15, ran_ue_id=2)
        mgr.add_pdu_session_setup(
            ran_ue_id=2,
            frame=4,
            time=0.2,
            cause_class="NORMAL",
            success=False,
            pdu_session_id=1,
        )

        rate = KPICalculator.pdu_session_success_rate(mgr.get_all_contexts())
        assert rate == 50.0

    def test_completion_rate(self):
        """Test completion rate calculation."""
        mgr = UEContextManager()
        # Complete UE
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_release(ran_ue_id=1, imsi=None, frame=2, time=0.1, cause_class=None)

        # Incomplete UE
        mgr.add_initial_ue_message(frame=3, time=0.2, ran_ue_id=2)

        rate = KPICalculator.completion_rate(mgr.get_all_contexts())
        assert rate == 50.0

    def test_procedure_timing(self):
        """Test procedure timing calculation."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_ics(ran_ue_id=1, frame=3, time=0.3, cause_class="NORMAL", success=True)
        mgr.add_pdu_session_setup(
            ran_ue_id=1,
            frame=4,
            time=0.5,
            cause_class="NORMAL",
            success=True,
            pdu_session_id=1,
        )

        timings = KPICalculator.procedure_timing(mgr.get_all_contexts())
        assert "registration" in timings
        assert "ics" in timings
        assert "pdu_session" in timings
        assert timings["registration"]["avg"] == pytest.approx(0.1)  # 0.1 - 0.0
        assert timings["ics"]["avg"] == pytest.approx(0.2)  # 0.3 - 0.1
        assert timings["pdu_session"]["avg"] == pytest.approx(0.2)  # 0.5 - 0.3

    def test_drop_rate_by_cause(self):
        """Test drop rate calculation by cause."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_initial_ue_message(frame=3, time=0.15, ran_ue_id=2)
        mgr.add_registration(
            ran_ue_id=2,
            imsi="223456789012345",
            frame=4,
            time=0.2,
            cause_class="NORMAL",
            success=False,
        )
        mgr.add_initial_ue_message(frame=5, time=0.25, ran_ue_id=3)
        mgr.add_registration(
            ran_ue_id=3,
            imsi="323456789012345",
            frame=6,
            time=0.3,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )

        drop_rates = KPICalculator.drop_rate_by_cause(mgr.get_all_contexts())
        assert drop_rates["NORMAL"] == 50.0
        assert drop_rates["ABNORMAL_RADIO"] == 100.0

    def test_success_rate_by_cause(self):
        """Test success rate by cause."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_initial_ue_message(frame=3, time=0.15, ran_ue_id=2)
        mgr.add_registration(
            ran_ue_id=2,
            imsi="223456789012345",
            frame=4,
            time=0.2,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_initial_ue_message(frame=5, time=0.25, ran_ue_id=3)
        mgr.add_registration(
            ran_ue_id=3,
            imsi="323456789012345",
            frame=6,
            time=0.3,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )

        success_rates = KPICalculator.success_rate_by_cause(mgr.get_all_contexts())
        assert success_rates["NORMAL"] == 100.0
        assert success_rates["ABNORMAL_RADIO"] == 0.0

    def test_event_count_by_type(self):
        """Test event counting by type."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_ics(ran_ue_id=1, frame=3, time=0.2, cause_class="NORMAL", success=True)

        counts = KPICalculator.event_count_by_type(mgr.get_all_contexts())
        assert counts[EventType.INITIAL_UE_MESSAGE.value] == 1
        assert counts[EventType.REGISTRATION_ATTEMPT.value] == 1
        assert counts[EventType.ICS_ATTEMPT.value] == 1

    def test_summary_stats(self):
        """Test comprehensive summary statistics."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        mgr.add_ics(ran_ue_id=1, frame=3, time=0.2, cause_class="NORMAL", success=True)
        mgr.add_release(ran_ue_id=1, imsi="123456789012345", frame=4, time=0.3, cause_class=None)

        stats = KPICalculator.summary_stats(mgr.get_all_contexts())
        assert stats["total_ues"] == 1
        assert stats["complete_ues"] == 1
        assert stats["completion_rate"] == 100.0
        assert stats["registration_success_rate"] == 100.0
        assert stats["ics_success_rate"] == 100.0


class TestFindingDetector:
    """Test finding detection functionality."""

    def test_detect_high_drop_rate(self):
        """Test detection of high drop rates."""
        mgr = UEContextManager()
        for i in range(10):
            mgr.add_initial_ue_message(frame=i * 2 + 1, time=float(i) * 0.1, ran_ue_id=i)
            mgr.add_registration(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 2 + 2,
                time=float(i) * 0.1 + 0.01,
                cause_class="ABNORMAL_RADIO",
                success=False,  # All fail
            )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        high_drop_findings = [
            f for f in findings if f.finding_type == FindingType.HIGH_DROP_RATE
        ]
        assert len(high_drop_findings) > 0
        assert high_drop_findings[0].metric_value == 100.0

    def test_detect_abnormal_cause_pattern(self):
        """Test detection of abnormal cause patterns."""
        mgr = UEContextManager()
        for i in range(20):
            mgr.add_initial_ue_message(frame=i * 2 + 1, time=float(i) * 0.05, ran_ue_id=i)
            mgr.add_registration(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 2 + 2,
                time=float(i) * 0.05 + 0.01,
                cause_class="ABNORMAL_RADIO" if i < 10 else "NORMAL",
                success=True,
            )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        abnormal_findings = [
            f
            for f in findings
            if f.finding_type == FindingType.ABNORMAL_CAUSE_PATTERN
        ]
        assert len(abnormal_findings) > 0

    def test_detect_repeated_failures(self):
        """Test detection of repeated failures."""
        mgr = UEContextManager()
        ctx = mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=2,
            time=0.1,
            success=False,
        )
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT, frame=3, time=0.2, success=False
        )
        ctx.add_event(
            event_type=EventType.PDU_SESSION_SETUP,
            frame=4,
            time=0.3,
            success=False,
        )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        failure_findings = [
            f
            for f in findings
            if f.finding_type == FindingType.REPEATED_FAILURES
        ]
        assert len(failure_findings) > 0

    def test_detect_slow_procedures(self):
        """Test detection of slow procedures."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=5.0,  # 5 seconds - very slow
            cause_class="NORMAL",
            success=True,
        )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        slow_findings = [
            f for f in findings if f.finding_type == FindingType.SLOW_PROCEDURE
        ]
        assert len(slow_findings) > 0

    def test_detect_incomplete_lifecycles(self):
        """Test detection of incomplete lifecycles."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)
        mgr.add_initial_ue_message(frame=2, time=0.1, ran_ue_id=2)
        mgr.add_release(ran_ue_id=2, imsi=None, frame=3, time=0.2, cause_class=None)

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        incomplete_findings = [
            f
            for f in findings
            if f.finding_type == FindingType.INCOMPLETE_LIFECYCLE
        ]
        assert len(incomplete_findings) > 0

    def test_detect_zero_success_rate_registration(self):
        """Test detection of zero registration success rate."""
        mgr = UEContextManager()
        for i in range(5):
            mgr.add_initial_ue_message(frame=i * 2 + 1, time=float(i) * 0.1, ran_ue_id=i)
            mgr.add_registration(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 2 + 2,
                time=float(i) * 0.1 + 0.01,
                cause_class="ABNORMAL_RADIO",
                success=False,  # All fail
            )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        zero_findings = [
            f
            for f in findings
            if f.finding_type == FindingType.ZERO_SUCCESS_RATE
            and f.procedure == "registration"
        ]
        assert len(zero_findings) > 0
        assert zero_findings[0].severity == FindingSeverity.CRITICAL

    def test_finding_sorting_by_score(self):
        """Test that findings are sorted by score."""
        mgr = UEContextManager()
        # Add many failures to trigger high drop rate
        for i in range(20):
            mgr.add_initial_ue_message(frame=i * 2 + 1, time=float(i) * 0.05, ran_ue_id=i)
            mgr.add_registration(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 2 + 2,
                time=float(i) * 0.05 + 0.01,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        assert len(findings) > 0

        # Verify sorted by score descending
        for i in range(len(findings) - 1):
            assert findings[i].score >= findings[i + 1].score

    def test_finding_severity_levels(self):
        """Test that findings have appropriate severity levels."""
        mgr = UEContextManager()
        # Add one incomplete UE (low severity)
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1)

        # Add registrations all failing (high severity)
        for i in range(10):
            mgr.add_registration(
                ran_ue_id=i + 10,
                imsi=f"1234567890123{i:02d}",
                frame=i + 2,
                time=float(i) * 0.1,
                cause_class="ABNORMAL_RADIO",
                success=False,
            )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        assert len(findings) > 0

        # Check that critical findings have high scores
        critical_findings = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        if critical_findings:
            assert all(f.score >= 80.0 for f in critical_findings)

    def test_finding_with_no_issues(self):
        """Test that no findings are generated for healthy trace."""
        mgr = UEContextManager()
        for i in range(3):
            mgr.add_initial_ue_message(frame=i * 10 + 1, time=float(i) * 1.0, ran_ue_id=i)
            mgr.add_registration(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 10 + 2,
                time=float(i) * 1.0 + 0.1,
                cause_class="NORMAL",
                success=True,
            )
            mgr.add_ics(
                ran_ue_id=i,
                frame=i * 10 + 3,
                time=float(i) * 1.0 + 0.2,
                cause_class="NORMAL",
                success=True,
            )
            mgr.add_release(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 10 + 4,
                time=float(i) * 1.0 + 0.3,
                cause_class=None,
            )

        findings = FindingDetector.detect_findings(mgr.get_all_contexts())
        # Healthy trace should have few or no critical/warning findings
        critical_warnings = [
            f
            for f in findings
            if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.WARNING]
        ]
        assert len(critical_warnings) == 0


class TestKPIFindingIntegration:
    """Test integration between KPI and finding detection."""

    def test_kpi_metrics_feed_findings(self):
        """Test that KPI metrics inform finding detection."""
        mgr = UEContextManager()
        contexts = mgr.get_all_contexts()

        # Empty should be healthy
        kpis = KPICalculator.summary_stats(contexts)
        findings = FindingDetector.detect_findings(contexts)

        assert kpis["total_ues"] == 0
        assert len(findings) == 0

    def test_complete_analysis_workflow(self):
        """Test complete workflow from UE contexts to findings."""
        mgr = UEContextManager()

        # Build a realistic scenario
        for i in range(5):
            mgr.add_initial_ue_message(frame=i * 20 + 1, time=float(i), ran_ue_id=i)
            success = i < 2  # First 2 succeed
            mgr.add_registration(
                ran_ue_id=i,
                imsi=f"1234567890123{i:02d}",
                frame=i * 20 + 2,
                time=float(i) + 0.1,
                cause_class="NORMAL" if success else "ABNORMAL_RADIO",
                success=success,
            )
            if success:
                mgr.add_ics(
                    ran_ue_id=i,
                    frame=i * 20 + 3,
                    time=float(i) + 0.2,
                    cause_class="NORMAL",
                    success=True,
                )
                mgr.add_release(
                    ran_ue_id=i,
                    imsi=f"1234567890123{i:02d}",
                    frame=i * 20 + 4,
                    time=float(i) + 0.3,
                    cause_class=None,
                )

        contexts = mgr.get_all_contexts()
        kpis = KPICalculator.summary_stats(contexts)
        findings = FindingDetector.detect_findings(contexts)

        # Verify KPIs
        assert kpis["total_ues"] == 5
        assert kpis["registration_success_rate"] == 40.0  # 2 out of 5
        assert kpis["completion_rate"] == 40.0

        # Verify findings detected
        assert len(findings) > 0
        assert any(f.severity == FindingSeverity.WARNING for f in findings)
