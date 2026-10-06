"""UE context manager for lifecycle tracking and aggregation.

Builds UEContext objects from decoded trace events, maintaining
a map of UEs by IMSI and RAN-UE-NGAP-ID for efficient lookup.
"""

from collections import defaultdict
from typing import Any

from app.models.ue_context import UEContext, EventType


class UEContextManager:
    """Manages UE lifecycle contexts from trace events.

    Maps UEs by identity and builds immutable lifecycle event logs
    for subsequent KPI calculation and finding detection.
    """

    def __init__(self):
        """Initialize empty context manager."""
        # Map from IMSI to UEContext
        self.by_imsi: dict[str, UEContext] = {}

        # Map from RAN-UE-NGAP-ID to UEContext (for matching w/o IMSI)
        self.by_ran_ue_id: dict[int, UEContext] = {}

        # Track UEs by initial frame for ordering
        self.by_initial_frame: dict[int, UEContext] = {}

        # In-progress tracking: RAN-UE-NGAP-ID -> UEContext (before IMSI known)
        self._pending: dict[int, UEContext] = {}

    def get_or_create(self, ran_ue_id: int | None = None,
                     imsi: str | None = None) -> UEContext:
        """Get existing UEContext or create new one.

        Args:
            ran_ue_id: NGAP RAN-UE-NGAP-ID
            imsi: NAS-derived IMSI (may be None initially)

        Returns:
            UEContext for this UE
        """
        # Try to find by IMSI if available
        if imsi and imsi in self.by_imsi:
            return self.by_imsi[imsi]

        # Try to find by RAN-UE-ID if available
        if ran_ue_id is not None and ran_ue_id in self.by_ran_ue_id:
            ctx = self.by_ran_ue_id[ran_ue_id]
            # Update IMSI if we now know it
            if imsi and ctx.imsi is None:
                ctx.imsi = imsi
                self.by_imsi[imsi] = ctx
            return ctx

        # Check pending contexts
        if ran_ue_id is not None and ran_ue_id in self._pending:
            ctx = self._pending[ran_ue_id]
            # Update IMSI if we now know it
            if imsi:
                ctx.imsi = imsi
                self.by_imsi[imsi] = ctx
            return ctx

        # Create new context
        ctx = UEContext(imsi=imsi, ran_ue_id=ran_ue_id)

        # Register in appropriate maps
        if imsi:
            self.by_imsi[imsi] = ctx
        if ran_ue_id is not None:
            self.by_ran_ue_id[ran_ue_id] = ctx
            self._pending[ran_ue_id] = ctx

        return ctx

    def add_initial_ue_message(self, frame: int, time: float,
                              ran_ue_id: int, imsi: str | None = None,
                              details: dict[str, Any] | None = None) -> UEContext:
        """Process InitialUEMessage event.

        Args:
            frame: Frame number
            time: Packet timestamp
            ran_ue_id: NGAP RAN-UE-NGAP-ID
            imsi: IMSI if available (may come from NAS PDU parsing)
            details: Additional metadata

        Returns:
            UEContext for this UE
        """
        ctx = self.get_or_create(ran_ue_id=ran_ue_id, imsi=imsi)

        # Mark initial event
        ctx.initial_frame = frame
        ctx.initial_time = time

        ctx.add_event(
            event_type=EventType.INITIAL_UE_MESSAGE,
            frame=frame,
            time=time,
            **(details or {})
        )

        self.by_initial_frame[frame] = ctx

        return ctx

    def add_registration(self, ran_ue_id: int | None, imsi: str | None,
                        frame: int, time: float,
                        cause_class: str | None,
                        success: bool,
                        details: dict[str, Any] | None = None) -> UEContext:
        """Process NAS Registration Complete event.

        Args:
            ran_ue_id: NGAP RAN-UE-NGAP-ID (may be None)
            imsi: IMSI from NAS Registration Request
            frame: Frame number
            time: Packet timestamp
            cause_class: Business category from Phase 1b
            success: True for Registration Accept, False for Reject
            details: Additional metadata

        Returns:
            UEContext for this UE
        """
        ctx = self.get_or_create(ran_ue_id=ran_ue_id, imsi=imsi)
        ctx.imsi = imsi  # Update IMSI if known

        ctx.add_event(
            event_type=EventType.REGISTRATION_ATTEMPT,
            frame=frame,
            time=time,
            cause_class=cause_class,
            success=success,
            message_type="registration_accept" if success else "registration_reject",
            **(details or {})
        )

        # Ensure indexed by IMSI if we now know it
        if imsi:
            self.by_imsi[imsi] = ctx

        return ctx

    def add_ics(self, ran_ue_id: int,
               frame: int, time: float,
               cause_class: str | None,
               success: bool,
               details: dict[str, Any] | None = None) -> UEContext:
        """Process Initial Context Setup response event.

        Args:
            ran_ue_id: NGAP RAN-UE-NGAP-ID
            frame: Frame number
            time: Packet timestamp
            cause_class: Business category (NORMAL, ABNORMAL_RADIO, etc.)
            success: True for ICS Success, False for ICS Failure
            details: Additional metadata

        Returns:
            UEContext for this UE
        """
        ctx = self.get_or_create(ran_ue_id=ran_ue_id)

        ctx.add_event(
            event_type=EventType.ICS_ATTEMPT,
            frame=frame,
            time=time,
            cause_class=cause_class,
            success=success,
            message_type="ics_success" if success else "ics_failure",
            **(details or {})
        )

        return ctx

    def add_pdu_session_setup(self, ran_ue_id: int,
                            frame: int, time: float,
                            cause_class: str | None,
                            success: bool,
                            pdu_session_id: int | None = None,
                            details: dict[str, Any] | None = None) -> UEContext:
        """Process PDU Session Establishment Complete event.

        Args:
            ran_ue_id: NGAP RAN-UE-NGAP-ID
            frame: Frame number
            time: Packet timestamp
            cause_class: Business category
            success: True for Setup Complete, False for Setup Failure
            pdu_session_id: PDU Session ID
            details: Additional metadata

        Returns:
            UEContext for this UE
        """
        ctx = self.get_or_create(ran_ue_id=ran_ue_id)

        ctx.add_event(
            event_type=EventType.PDU_SESSION_SETUP,
            frame=frame,
            time=time,
            cause_class=cause_class,
            success=success,
            pdu_session_id=pdu_session_id,
            **(details or {})
        )

        return ctx

    def add_release(self, ran_ue_id: int | None, imsi: str | None,
                   frame: int, time: float,
                   cause_class: str | None,
                   details: dict[str, Any] | None = None) -> UEContext:
        """Process UE Release Complete event.

        Args:
            ran_ue_id: NGAP RAN-UE-NGAP-ID
            imsi: IMSI if known
            frame: Frame number
            time: Packet timestamp
            cause_class: Business category
            details: Additional metadata

        Returns:
            UEContext for this UE
        """
        ctx = self.get_or_create(ran_ue_id=ran_ue_id, imsi=imsi)

        ctx.add_event(
            event_type=EventType.RELEASE_COMPLETE,
            frame=frame,
            time=time,
            cause_class=cause_class,
            **(details or {})
        )

        # Clean up pending if we have RAN-UE-ID
        if ran_ue_id is not None and ran_ue_id in self._pending:
            del self._pending[ran_ue_id]

        return ctx

    def get_all_contexts(self) -> list[UEContext]:
        """Get all UE contexts sorted by initial frame.

        Returns:
            Sorted list of UEContexts
        """
        return sorted(
            self.by_initial_frame.values(),
            key=lambda ctx: ctx.initial_frame
        )

    def get_context_by_imsi(self, imsi: str) -> UEContext | None:
        """Look up UEContext by IMSI."""
        return self.by_imsi.get(imsi)

    def get_context_by_ran_ue_id(self, ran_ue_id: int) -> UEContext | None:
        """Look up UEContext by RAN-UE-NGAP-ID."""
        return self.by_ran_ue_id.get(ran_ue_id)

    def statistics(self) -> dict[str, Any]:
        """Calculate statistics over all contexts.

        Returns:
            Dict with counts and rates
        """
        all_ctx = self.get_all_contexts()

        registration_attempts = sum(
            1 for ctx in all_ctx
            if ctx.registration_success() is not None
        )
        registration_success = sum(
            1 for ctx in all_ctx
            if ctx.registration_success() is True
        )

        ics_attempts = sum(
            1 for ctx in all_ctx
            if ctx.ics_success() is not None
        )
        ics_success = sum(
            1 for ctx in all_ctx
            if ctx.ics_success() is True
        )

        complete_contexts = sum(
            1 for ctx in all_ctx
            if ctx.is_complete()
        )

        return {
            "total_ues": len(all_ctx),
            "complete_contexts": complete_contexts,
            "registration_attempts": registration_attempts,
            "registration_success": registration_success,
            "registration_success_rate": (
                registration_success / registration_attempts
                if registration_attempts > 0 else 0
            ),
            "ics_attempts": ics_attempts,
            "ics_success": ics_success,
            "ics_success_rate": (
                ics_success / ics_attempts
                if ics_attempts > 0 else 0
            ),
        }
