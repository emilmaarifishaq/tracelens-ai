"""KPI calculation from UE lifecycle contexts.

Calculates key performance indicators including success rates, procedure timing,
and drop rates by cause classification.
"""

from typing import Any

from app.models.ue_context import UEContext, EventType


class KPICalculator:
    """Calculates KPIs from UE contexts.

    Computes aggregate metrics across all UEs including success rates,
    procedure timing, and cause-specific analysis.
    """

    @staticmethod
    def registration_success_rate(
        contexts: list[UEContext], cause_class: str | None = None
    ) -> float:
        """Calculate registration success rate.

        Args:
            contexts: List of UE contexts
            cause_class: Filter by cause class (e.g., "NORMAL", "ABNORMAL_RADIO")

        Returns:
            Success rate as percentage (0-100)
        """
        if not contexts:
            return 0.0

        attempted = 0
        succeeded = 0

        for ctx in contexts:
            for event in ctx.events:
                if event["type"] == EventType.REGISTRATION_ATTEMPT:
                    event_cause = event.get("cause_class")
                    if cause_class and event_cause != cause_class:
                        continue
                    attempted += 1
                    if event.get("success") is True:
                        succeeded += 1

        return (succeeded / attempted * 100) if attempted > 0 else 0.0

    @staticmethod
    def ics_success_rate(
        contexts: list[UEContext], cause_class: str | None = None
    ) -> float:
        """Calculate ICS success rate.

        Args:
            contexts: List of UE contexts
            cause_class: Filter by cause class

        Returns:
            Success rate as percentage (0-100)
        """
        if not contexts:
            return 0.0

        attempted = 0
        succeeded = 0

        for ctx in contexts:
            for event in ctx.events:
                if event["type"] == EventType.ICS_ATTEMPT:
                    event_cause = event.get("cause_class")
                    if cause_class and event_cause != cause_class:
                        continue
                    attempted += 1
                    if event.get("success") is True:
                        succeeded += 1

        return (succeeded / attempted * 100) if attempted > 0 else 0.0

    @staticmethod
    def pdu_session_success_rate(
        contexts: list[UEContext], cause_class: str | None = None
    ) -> float:
        """Calculate PDU session setup success rate.

        Args:
            contexts: List of UE contexts
            cause_class: Filter by cause class

        Returns:
            Success rate as percentage (0-100)
        """
        if not contexts:
            return 0.0

        attempted = 0
        succeeded = 0

        for ctx in contexts:
            for event in ctx.events:
                if event["type"] == EventType.PDU_SESSION_SETUP:
                    event_cause = event.get("cause_class")
                    if cause_class and event_cause != cause_class:
                        continue
                    attempted += 1
                    if event.get("success") is True:
                        succeeded += 1

        return (succeeded / attempted * 100) if attempted > 0 else 0.0

    @staticmethod
    def completion_rate(contexts: list[UEContext]) -> float:
        """Calculate percentage of complete UE lifecycles.

        Args:
            contexts: List of UE contexts

        Returns:
            Completion rate as percentage (0-100)
        """
        if not contexts:
            return 0.0

        complete = sum(1 for ctx in contexts if ctx.is_complete())
        return (complete / len(contexts) * 100) if contexts else 0.0

    @staticmethod
    def procedure_timing(
        contexts: list[UEContext],
    ) -> dict[str, dict[str, float]]:
        """Calculate timing metrics for each procedure.

        Returns timing stats (min, max, avg, median) for:
        - registration: time from initial to registration response
        - ics: time from registration to ICS response
        - pdu: time from ICS to PDU session response
        - total: time from initial to release

        Args:
            contexts: List of UE contexts

        Returns:
            Dict mapping procedure names to {min, max, avg, median} timings in seconds
        """
        if not contexts:
            return {}

        registration_times = []
        ics_times = []
        pdu_times = []
        total_times = []

        for ctx in contexts:
            if len(ctx.events) < 1 or ctx.initial_frame == 0:
                continue

            # Find registration time (from initial to registration)
            reg_event = next(
                (e for e in ctx.events if e["type"] == EventType.REGISTRATION_ATTEMPT),
                None,
            )
            if reg_event:
                registration_times.append(reg_event["time"] - ctx.initial_time)

            # Find ICS time (from registration to ICS)
            ics_event = next(
                (e for e in ctx.events if e["type"] == EventType.ICS_ATTEMPT), None
            )
            if reg_event and ics_event:
                ics_times.append(ics_event["time"] - reg_event["time"])

            # Find PDU time (from ICS to first PDU session)
            pdu_event = next(
                (e for e in ctx.events if e["type"] == EventType.PDU_SESSION_SETUP),
                None,
            )
            if ics_event and pdu_event:
                pdu_times.append(pdu_event["time"] - ics_event["time"])

            # Total lifetime
            lifetime = ctx.lifetime_seconds()
            if lifetime is not None:
                total_times.append(lifetime)

        return {
            "registration": _timing_stats(registration_times),
            "ics": _timing_stats(ics_times),
            "pdu_session": _timing_stats(pdu_times),
            "total": _timing_stats(total_times),
        }

    @staticmethod
    def drop_rate_by_cause(
        contexts: list[UEContext],
    ) -> dict[str, float]:
        """Calculate drop rate for each cause class.

        Analyzes failure rate per cause classification across all procedures.

        Args:
            contexts: List of UE contexts

        Returns:
            Dict mapping cause class to failure percentage
        """
        if not contexts:
            return {}

        cause_stats: dict[str, dict[str, int]] = {}

        for ctx in contexts:
            for event in ctx.events:
                cause = event.get("cause_class")
                if not cause:
                    continue

                if cause not in cause_stats:
                    cause_stats[cause] = {"total": 0, "failures": 0}

                cause_stats[cause]["total"] += 1
                if event.get("success") is False:
                    cause_stats[cause]["failures"] += 1

        return {
            cause: (stats["failures"] / stats["total"] * 100)
            if stats["total"] > 0
            else 0.0
            for cause, stats in cause_stats.items()
        }

    @staticmethod
    def success_rate_by_cause(
        contexts: list[UEContext],
    ) -> dict[str, float]:
        """Calculate success rate for each cause class.

        Args:
            contexts: List of UE contexts

        Returns:
            Dict mapping cause class to success percentage
        """
        if not contexts:
            return {}

        cause_stats: dict[str, dict[str, int]] = {}

        for ctx in contexts:
            for event in ctx.events:
                cause = event.get("cause_class")
                if not cause:
                    continue

                if cause not in cause_stats:
                    cause_stats[cause] = {"total": 0, "successes": 0}

                cause_stats[cause]["total"] += 1
                if event.get("success") is True:
                    cause_stats[cause]["successes"] += 1

        return {
            cause: (stats["successes"] / stats["total"] * 100)
            if stats["total"] > 0
            else 0.0
            for cause, stats in cause_stats.items()
        }

    @staticmethod
    def event_count_by_type(contexts: list[UEContext]) -> dict[str, int]:
        """Count events by type across all contexts.

        Args:
            contexts: List of UE contexts

        Returns:
            Dict mapping event type to count
        """
        if not contexts:
            return {}

        counts: dict[str, int] = {}
        for ctx in contexts:
            for event in ctx.events:
                event_type = event.get("type", "unknown")
                counts[event_type] = counts.get(event_type, 0) + 1

        return counts

    @staticmethod
    def failure_rate_by_type(contexts: list[UEContext]) -> dict[str, float]:
        """Calculate failure rate for each event type.

        Args:
            contexts: List of UE contexts

        Returns:
            Dict mapping event type to failure percentage
        """
        if not contexts:
            return {}

        type_stats: dict[str, dict[str, int]] = {}

        for ctx in contexts:
            for event in ctx.events:
                event_type = event.get("type", "unknown")
                if not event.get("success") is None:
                    if event_type not in type_stats:
                        type_stats[event_type] = {"total": 0, "failures": 0}
                    type_stats[event_type]["total"] += 1
                    if event.get("success") is False:
                        type_stats[event_type]["failures"] += 1

        return {
            event_type: (stats["failures"] / stats["total"] * 100)
            if stats["total"] > 0
            else 0.0
            for event_type, stats in type_stats.items()
        }

    @staticmethod
    def summary_stats(contexts: list[UEContext]) -> dict[str, Any]:
        """Generate comprehensive KPI summary.

        Args:
            contexts: List of UE contexts

        Returns:
            Dict with all major KPIs
        """
        return {
            "total_ues": len(contexts),
            "complete_ues": sum(1 for ctx in contexts if ctx.is_complete()),
            "completion_rate": KPICalculator.completion_rate(contexts),
            "registration_success_rate": KPICalculator.registration_success_rate(
                contexts
            ),
            "ics_success_rate": KPICalculator.ics_success_rate(contexts),
            "pdu_session_success_rate": KPICalculator.pdu_session_success_rate(
                contexts
            ),
            "procedure_timing": KPICalculator.procedure_timing(contexts),
            "drop_rate_by_cause": KPICalculator.drop_rate_by_cause(contexts),
            "success_rate_by_cause": KPICalculator.success_rate_by_cause(contexts),
            "event_counts": KPICalculator.event_count_by_type(contexts),
            "failure_rate_by_type": KPICalculator.failure_rate_by_type(contexts),
        }


def _timing_stats(times: list[float]) -> dict[str, float]:
    """Calculate min, max, avg, median for timing list.

    Args:
        times: List of timing values in seconds

    Returns:
        Dict with min, max, avg, median, count
    """
    if not times:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "median": 0.0, "count": 0}

    sorted_times = sorted(times)
    count = len(sorted_times)
    avg = sum(times) / count
    median = (
        sorted_times[count // 2]
        if count % 2 == 1
        else (sorted_times[count // 2 - 1] + sorted_times[count // 2]) / 2
    )

    return {
        "min": sorted_times[0],
        "max": sorted_times[-1],
        "avg": avg,
        "median": median,
        "count": count,
    }
