"""UE context lifecycle tracking for 5G trace analysis.

Tracks UE state transitions from InitialUEMessage through Release,
maintaining immutable event logs for KPI calculation and finding detection.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class UEState(str, Enum):
    """UE lifecycle state."""
    INITIAL = "INITIAL"  # After InitialUEMessage
    REGISTERED = "REGISTERED"  # After NAS Registration Accept
    IN_SERVICE = "IN_SERVICE"  # After ICS Success
    RELEASED = "RELEASED"  # After Release Complete


class EventType(str, Enum):
    """Lifecycle event types."""
    INITIAL_UE_MESSAGE = "initial_ue_message"
    REGISTRATION_ATTEMPT = "registration_attempt"
    ICS_ATTEMPT = "ics_attempt"
    PDU_SESSION_SETUP = "pdu_session_setup"
    RELEASE_COMPLETE = "release_complete"


@dataclass
class UEContext:
    """Immutable UE lifecycle tracking.

    Events are append-only; once added they cannot be modified.
    Derived metrics (state, success rates) are calculated on-demand.
    """

    # Identity (extracted from messages)
    imsi: str | None = None
    ran_ue_id: int | None = None
    amf_ue_id: int | None = None

    # Initial event
    initial_frame: int = 0
    initial_time: float = 0.0

    # Lifecycle events (immutable append-only log)
    events: list[dict[str, Any]] = field(default_factory=list)
    # Each event: {
    #   type: EventType
    #   frame: int
    #   time: float
    #   cause_class: str | None
    #   success: bool | None (for registration/ICS/pdu)
    #   details: dict (protocol-specific data)
    # }

    def add_event(self, event_type: str, frame: int, time: float,
                 cause_class: str | None = None,
                 success: bool | None = None,
                 **details) -> None:
        """Append immutable lifecycle event.

        Args:
            event_type: Type of event (EventType enum value)
            frame: Frame number in trace
            time: Packet timestamp
            cause_class: Business category from Phase 1b (e.g., NORMAL, ABNORMAL_RADIO)
            success: True for successful procedures, False for failures
            **details: Protocol-specific metadata
        """
        self.events.append({
            "type": event_type,
            "frame": frame,
            "time": time,
            "cause_class": cause_class,
            "success": success,
            "details": details,
        })

    def get_state(self) -> UEState:
        """Get current UE state based on lifecycle events.

        Returns:
            Current state: INITIAL → REGISTERED → IN_SERVICE → RELEASED
        """
        if not self.events:
            return UEState.INITIAL

        # Scan events in order
        has_registration = False
        has_ics_success = False
        has_release = False

        for event in self.events:
            event_type = event["type"]
            success = event.get("success")

            if event_type == EventType.REGISTRATION_ATTEMPT:
                if success:
                    has_registration = True
            elif event_type == EventType.ICS_ATTEMPT:
                if success:
                    has_ics_success = True
            elif event_type == EventType.RELEASE_COMPLETE:
                has_release = True

        if has_release:
            return UEState.RELEASED
        if has_ics_success:
            return UEState.IN_SERVICE
        if has_registration:
            return UEState.REGISTERED
        return UEState.INITIAL

    def is_complete(self) -> bool:
        """Check if UE has proper lifecycle completion.

        Returns:
            True if context has both InitialUEMessage and Release
        """
        has_initial = self.initial_frame > 0
        has_release = any(e["type"] == EventType.RELEASE_COMPLETE
                         for e in self.events)
        return has_initial and has_release

    def registration_success(self) -> bool | None:
        """Check if NAS Registration succeeded.

        Returns:
            True if Registration Accept seen, False if Reject, None if not attempted
        """
        for event in self.events:
            if event["type"] == EventType.REGISTRATION_ATTEMPT:
                return event.get("success")
        return None

    def registration_cause(self) -> str | None:
        """Get cause classification of registration.

        Returns:
            Business category (NORMAL, ABNORMAL_CONFIG, etc.) or None
        """
        for event in self.events:
            if event["type"] == EventType.REGISTRATION_ATTEMPT:
                return event.get("cause_class")
        return None

    def ics_success(self) -> bool | None:
        """Check if Initial Context Setup succeeded.

        Returns:
            True if ICS Success seen, False if Failure, None if not attempted
        """
        for event in self.events:
            if event["type"] == EventType.ICS_ATTEMPT:
                return event.get("success")
        return None

    def ics_cause(self) -> str | None:
        """Get cause classification of ICS.

        Returns:
            Business category or None
        """
        for event in self.events:
            if event["type"] == EventType.ICS_ATTEMPT:
                return event.get("cause_class")
        return None

    def pdu_sessions(self) -> list[dict[str, Any]]:
        """Get all PDU session setup events.

        Returns:
            List of PDU session events with setup status and cause
        """
        return [e for e in self.events
                if e["type"] == EventType.PDU_SESSION_SETUP]

    def lifetime_seconds(self) -> float | None:
        """Calculate UE lifetime from initial message to release.

        Returns:
            Duration in seconds, or None if not released
        """
        if not self.is_complete():
            return None

        for event in reversed(self.events):
            if event["type"] == EventType.RELEASE_COMPLETE:
                return event["time"] - self.initial_time

        return None

    def event_count(self) -> int:
        """Get total number of lifecycle events."""
        return len(self.events)

    def failed_event_count(self) -> int:
        """Count events with failures or abnormal causes."""
        count = 0
        for event in self.events:
            success = event.get("success")
            cause = event.get("cause_class")

            # Count failures
            if success is False:
                count += 1
            # Count abnormal causes
            elif cause and "ABNORMAL" in cause:
                count += 1

        return count
