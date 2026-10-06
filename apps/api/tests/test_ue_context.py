"""Phase 2a: UE Context lifecycle tracking tests."""

import pytest
from app.models.ue_context import UEContext, UEState, EventType
from app.services.ue_manager import UEContextManager


class TestUEContextBasics:
    """Test UEContext model fundamentals."""

    def test_ue_context_creation(self):
        """Test creating a UEContext."""
        ctx = UEContext(imsi="123456789012345", ran_ue_id=42)
        assert ctx.imsi == "123456789012345"
        assert ctx.ran_ue_id == 42
        assert ctx.amf_ue_id is None
        assert ctx.initial_frame == 0
        assert ctx.initial_time == 0.0
        assert len(ctx.events) == 0

    def test_ue_context_defaults(self):
        """Test UEContext with default values."""
        ctx = UEContext()
        assert ctx.imsi is None
        assert ctx.ran_ue_id is None
        assert ctx.amf_ue_id is None

    def test_add_event_immutable_append(self):
        """Test that events are appended to immutable log."""
        ctx = UEContext(imsi="123456789012345")
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=10,
            time=1.5,
            cause_class="NORMAL",
            success=True,
        )
        assert len(ctx.events) == 1
        assert ctx.events[0]["type"] == EventType.REGISTRATION_ATTEMPT
        assert ctx.events[0]["success"] is True

    def test_add_multiple_events(self):
        """Test adding multiple events maintains order."""
        ctx = UEContext()
        ctx.add_event(EventType.INITIAL_UE_MESSAGE, 1, 0.1)
        ctx.add_event(EventType.REGISTRATION_ATTEMPT, 2, 0.2, success=True)
        ctx.add_event(EventType.ICS_ATTEMPT, 3, 0.3, success=True)
        assert len(ctx.events) == 3
        assert ctx.events[0]["type"] == EventType.INITIAL_UE_MESSAGE
        assert ctx.events[1]["type"] == EventType.REGISTRATION_ATTEMPT
        assert ctx.events[2]["type"] == EventType.ICS_ATTEMPT


class TestUEStateTransitions:
    """Test UE state transitions."""

    def test_initial_state(self):
        """Test initial state with no events."""
        ctx = UEContext()
        assert ctx.get_state() == UEState.INITIAL

    def test_state_after_registration(self):
        """Test state transitions to REGISTERED after successful registration."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            success=True,
        )
        assert ctx.get_state() == UEState.REGISTERED

    def test_state_after_ics_success(self):
        """Test state transitions to IN_SERVICE after successful ICS."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            success=True,
        )
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=2,
            time=0.2,
            success=True,
        )
        assert ctx.get_state() == UEState.IN_SERVICE

    def test_state_after_release(self):
        """Test state transitions to RELEASED."""
        ctx = UEContext()
        ctx.add_event(EventType.INITIAL_UE_MESSAGE, 1, 0.1)
        ctx.add_event(EventType.REGISTRATION_ATTEMPT, 2, 0.2, success=True)
        ctx.add_event(EventType.ICS_ATTEMPT, 3, 0.3, success=True)
        ctx.add_event(EventType.RELEASE_COMPLETE, 4, 0.4)
        assert ctx.get_state() == UEState.RELEASED

    def test_registration_reject_stays_initial(self):
        """Test that rejected registration doesn't advance state."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            success=False,
        )
        assert ctx.get_state() == UEState.INITIAL

    def test_ics_failure_stays_registered(self):
        """Test that ICS failure doesn't advance to IN_SERVICE."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            success=True,
        )
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=2,
            time=0.2,
            success=False,
        )
        assert ctx.get_state() == UEState.REGISTERED


class TestUELifecycleQueries:
    """Test lifecycle query methods."""

    def test_is_complete_with_initial_and_release(self):
        """Test is_complete() for properly closed lifecycle."""
        ctx = UEContext()
        ctx.initial_frame = 1
        ctx.add_event(EventType.RELEASE_COMPLETE, 10, 1.0)
        assert ctx.is_complete() is True

    def test_is_complete_without_initial(self):
        """Test is_complete() without InitialUEMessage."""
        ctx = UEContext()
        ctx.add_event(EventType.RELEASE_COMPLETE, 10, 1.0)
        assert ctx.is_complete() is False

    def test_is_complete_without_release(self):
        """Test is_complete() without Release."""
        ctx = UEContext()
        ctx.initial_frame = 1
        assert ctx.is_complete() is False

    def test_registration_success_true(self):
        """Test registration_success() for successful registration."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            success=True,
        )
        assert ctx.registration_success() is True

    def test_registration_success_false(self):
        """Test registration_success() for rejected registration."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            success=False,
        )
        assert ctx.registration_success() is False

    def test_registration_success_none(self):
        """Test registration_success() when no registration attempted."""
        ctx = UEContext()
        assert ctx.registration_success() is None

    def test_registration_cause(self):
        """Test registration_cause() extraction."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=1,
            time=0.1,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )
        assert ctx.registration_cause() == "ABNORMAL_RADIO"

    def test_ics_success_true(self):
        """Test ics_success() for successful ICS."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=1,
            time=0.1,
            success=True,
        )
        assert ctx.ics_success() is True

    def test_ics_success_false(self):
        """Test ics_success() for failed ICS."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=1,
            time=0.1,
            success=False,
        )
        assert ctx.ics_success() is False

    def test_ics_cause(self):
        """Test ics_cause() extraction."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=1,
            time=0.1,
            cause_class="ABNORMAL_RESOURCE",
            success=False,
        )
        assert ctx.ics_cause() == "ABNORMAL_RESOURCE"

    def test_pdu_sessions(self):
        """Test pdu_sessions() extraction."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.PDU_SESSION_SETUP,
            frame=1,
            time=0.1,
            success=True,
            pdu_session_id=1,
        )
        ctx.add_event(
            event_type=EventType.PDU_SESSION_SETUP,
            frame=2,
            time=0.2,
            success=False,
            pdu_session_id=2,
        )
        pdus = ctx.pdu_sessions()
        assert len(pdus) == 2
        assert pdus[0]["success"] is True
        assert pdus[1]["success"] is False

    def test_lifetime_seconds(self):
        """Test lifetime_seconds() calculation."""
        ctx = UEContext()
        ctx.initial_frame = 1
        ctx.initial_time = 0.0
        ctx.add_event(EventType.RELEASE_COMPLETE, 10, 5.0)
        assert ctx.lifetime_seconds() == 5.0

    def test_lifetime_seconds_incomplete(self):
        """Test lifetime_seconds() for incomplete lifecycle."""
        ctx = UEContext()
        ctx.initial_frame = 1
        ctx.initial_time = 0.0
        assert ctx.lifetime_seconds() is None

    def test_event_count(self):
        """Test event_count()."""
        ctx = UEContext()
        assert ctx.event_count() == 0
        ctx.add_event(EventType.INITIAL_UE_MESSAGE, 1, 0.1)
        ctx.add_event(EventType.REGISTRATION_ATTEMPT, 2, 0.2)
        assert ctx.event_count() == 2

    def test_failed_event_count(self):
        """Test failed_event_count()."""
        ctx = UEContext()
        ctx.add_event(EventType.REGISTRATION_ATTEMPT, 1, 0.1, success=True)
        ctx.add_event(EventType.ICS_ATTEMPT, 2, 0.2, success=False)
        ctx.add_event(
            event_type=EventType.PDU_SESSION_SETUP,
            frame=3,
            time=0.3,
            cause_class="ABNORMAL_PROTOCOL",
            success=False,
        )
        assert ctx.failed_event_count() == 2

    def test_failed_event_count_abnormal_causes(self):
        """Test failed_event_count() with abnormal causes."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=1,
            time=0.1,
            cause_class="ABNORMAL_RADIO",
            success=True,
        )
        ctx.add_event(
            event_type=EventType.PDU_SESSION_SETUP,
            frame=2,
            time=0.2,
            cause_class="ABNORMAL_RESOURCE",
            success=True,
        )
        assert ctx.failed_event_count() == 2


class TestUEContextManager:
    """Test UEContextManager aggregation and lookup."""

    def test_manager_creation(self):
        """Test creating a manager."""
        mgr = UEContextManager()
        assert len(mgr.get_all_contexts()) == 0

    def test_get_or_create_by_imsi(self):
        """Test creating context by IMSI."""
        mgr = UEContextManager()
        ctx1 = mgr.get_or_create(imsi="123456789012345")
        ctx2 = mgr.get_or_create(imsi="123456789012345")
        assert ctx1 is ctx2
        assert ctx1.imsi == "123456789012345"

    def test_get_or_create_by_ran_ue_id(self):
        """Test creating context by RAN-UE-ID."""
        mgr = UEContextManager()
        ctx1 = mgr.get_or_create(ran_ue_id=42)
        ctx2 = mgr.get_or_create(ran_ue_id=42)
        assert ctx1 is ctx2
        assert ctx1.ran_ue_id == 42

    def test_get_or_create_promotes_pending(self):
        """Test that pending context is promoted when IMSI becomes known."""
        mgr = UEContextManager()
        ctx1 = mgr.get_or_create(ran_ue_id=42)  # Creates pending
        ctx2 = mgr.get_or_create(ran_ue_id=42, imsi="123456789012345")  # Promotes it
        assert ctx1 is ctx2
        assert ctx2.imsi == "123456789012345"
        assert mgr.get_context_by_imsi("123456789012345") is ctx2

    def test_add_initial_ue_message(self):
        """Test adding InitialUEMessage."""
        mgr = UEContextManager()
        ctx = mgr.add_initial_ue_message(
            frame=1, time=0.1, ran_ue_id=42, imsi="123456789012345"
        )
        assert ctx.initial_frame == 1
        assert ctx.initial_time == 0.1
        assert ctx.ran_ue_id == 42
        assert ctx.imsi == "123456789012345"

    def test_add_registration(self):
        """Test adding registration event."""
        mgr = UEContextManager()
        ctx = mgr.add_registration(
            ran_ue_id=42,
            imsi="123456789012345",
            frame=2,
            time=0.2,
            cause_class="NORMAL",
            success=True,
        )
        assert ctx.registration_success() is True
        assert ctx.registration_cause() == "NORMAL"

    def test_add_ics(self):
        """Test adding ICS event."""
        mgr = UEContextManager()
        ctx = mgr.add_ics(
            ran_ue_id=42,
            frame=3,
            time=0.3,
            cause_class="NORMAL",
            success=True,
        )
        assert ctx.ics_success() is True
        assert ctx.ics_cause() == "NORMAL"

    def test_add_pdu_session_setup(self):
        """Test adding PDU session setup event."""
        mgr = UEContextManager()
        ctx = mgr.add_pdu_session_setup(
            ran_ue_id=42,
            frame=4,
            time=0.4,
            cause_class="NORMAL",
            success=True,
            pdu_session_id=1,
        )
        pdus = ctx.pdu_sessions()
        assert len(pdus) == 1
        assert pdus[0]["success"] is True

    def test_add_release(self):
        """Test adding release event."""
        mgr = UEContextManager()
        ctx = mgr.add_release(
            ran_ue_id=42,
            imsi="123456789012345",
            frame=5,
            time=0.5,
            cause_class="NORMAL",
        )
        assert ctx.get_state() == UEState.RELEASED

    def test_get_context_by_imsi(self):
        """Test lookup by IMSI."""
        mgr = UEContextManager()
        ctx = mgr.add_registration(
            ran_ue_id=42,
            imsi="123456789012345",
            frame=1,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        found = mgr.get_context_by_imsi("123456789012345")
        assert found is ctx

    def test_get_context_by_ran_ue_id(self):
        """Test lookup by RAN-UE-ID."""
        mgr = UEContextManager()
        ctx = mgr.add_initial_ue_message(frame=1, time=0.1, ran_ue_id=42)
        found = mgr.get_context_by_ran_ue_id(42)
        assert found is ctx

    def test_get_all_contexts_sorted(self):
        """Test that get_all_contexts() returns sorted by initial frame."""
        mgr = UEContextManager()
        mgr.add_initial_ue_message(frame=10, time=0.1, ran_ue_id=1)
        mgr.add_initial_ue_message(frame=5, time=0.05, ran_ue_id=2)
        mgr.add_initial_ue_message(frame=15, time=0.15, ran_ue_id=3)
        contexts = mgr.get_all_contexts()
        assert len(contexts) == 3
        assert contexts[0].ran_ue_id == 2
        assert contexts[1].ran_ue_id == 1
        assert contexts[2].ran_ue_id == 3

    def test_pending_cleanup_on_release(self):
        """Test that pending contexts are cleaned up on release."""
        mgr = UEContextManager()
        ctx = mgr.get_or_create(ran_ue_id=42)
        mgr.add_release(ran_ue_id=42, imsi=None, frame=1, time=0.1, cause_class=None)
        # Pending should be cleaned up after release
        assert 42 not in mgr._pending

    def test_statistics(self):
        """Test statistics calculation."""
        mgr = UEContextManager()
        # Add first UE with successful registration
        mgr.add_initial_ue_message(frame=1, time=0.0, ran_ue_id=1, imsi="123456789012345")
        mgr.add_registration(
            ran_ue_id=1,
            imsi="123456789012345",
            frame=2,
            time=0.1,
            cause_class="NORMAL",
            success=True,
        )
        # Add successful ICS
        mgr.add_ics(ran_ue_id=1, frame=3, time=0.2, cause_class="NORMAL", success=True)

        # Add second UE with failed registration
        mgr.add_initial_ue_message(frame=4, time=0.25, ran_ue_id=2, imsi="223456789012345")
        mgr.add_registration(
            ran_ue_id=2,
            imsi="223456789012345",
            frame=5,
            time=0.3,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )

        stats = mgr.statistics()
        assert stats["total_ues"] == 2
        assert stats["registration_attempts"] == 2
        assert stats["registration_success"] == 1
        assert stats["ics_attempts"] == 1
        assert stats["ics_success"] == 1

    def test_complete_lifecycle(self):
        """Test a complete UE lifecycle."""
        mgr = UEContextManager()
        # Initial UE Message
        ctx = mgr.add_initial_ue_message(
            frame=1, time=0.1, ran_ue_id=42, imsi="123456789012345"
        )
        # Registration
        mgr.add_registration(
            ran_ue_id=42,
            imsi="123456789012345",
            frame=2,
            time=0.2,
            cause_class="NORMAL",
            success=True,
        )
        # ICS
        mgr.add_ics(
            ran_ue_id=42,
            frame=3,
            time=0.3,
            cause_class="NORMAL",
            success=True,
        )
        # PDU Session
        mgr.add_pdu_session_setup(
            ran_ue_id=42,
            frame=4,
            time=0.4,
            cause_class="NORMAL",
            success=True,
            pdu_session_id=1,
        )
        # Release
        mgr.add_release(
            ran_ue_id=42,
            imsi="123456789012345",
            frame=5,
            time=0.5,
            cause_class="NORMAL",
        )

        # Verify complete lifecycle
        assert ctx.is_complete() is True
        assert ctx.get_state() == UEState.RELEASED
        assert ctx.registration_success() is True
        assert ctx.ics_success() is True
        assert len(ctx.pdu_sessions()) == 1
        assert ctx.lifetime_seconds() == 0.4


class TestUEContextEdgeCases:
    """Test edge cases and error handling."""

    def test_duplicate_events(self):
        """Test handling of duplicate events."""
        ctx = UEContext()
        ctx.add_event(EventType.REGISTRATION_ATTEMPT, 1, 0.1, success=True)
        ctx.add_event(EventType.REGISTRATION_ATTEMPT, 2, 0.2, success=False)
        # Both should be in log; query returns first
        assert len(ctx.events) == 2
        assert ctx.registration_success() is True

    def test_release_after_already_released(self):
        """Test adding release to already released UE."""
        mgr = UEContextManager()
        ctx = mgr.add_release(ran_ue_id=42, imsi=None, frame=1, time=0.1, cause_class=None)
        ctx2 = mgr.add_release(ran_ue_id=42, imsi=None, frame=2, time=0.2, cause_class=None)
        assert ctx is ctx2
        assert len(ctx.events) == 2

    def test_ue_without_imsi(self):
        """Test UE tracked only by RAN-UE-ID without IMSI."""
        mgr = UEContextManager()
        ctx = mgr.add_initial_ue_message(frame=1, time=0.1, ran_ue_id=42)
        mgr.add_registration(
            ran_ue_id=42,
            imsi=None,
            frame=2,
            time=0.2,
            cause_class="ABNORMAL_RADIO",
            success=False,
        )
        # Should still be accessible by RAN-UE-ID
        found = mgr.get_context_by_ran_ue_id(42)
        assert found is ctx
        assert ctx.imsi is None

    def test_events_with_none_fields(self):
        """Test adding events with None optional fields."""
        ctx = UEContext()
        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=1,
            time=0.1,
            cause_class=None,
            success=None,
        )
        assert len(ctx.events) == 1
        assert ctx.events[0]["cause_class"] is None
        assert ctx.events[0]["success"] is None
