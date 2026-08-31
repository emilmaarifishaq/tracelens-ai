from app.models.trace import TraceAnalysis


DIAMETER_ERROR_CODES = {
    "5001": "DIAMETER_ERROR_USER_UNKNOWN",
    "5003": "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
    "5004": "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
    "5005": "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
}

GTPV2_FAILURE_CAUSES = {
    "64": "Context Not Found",
    "65": "Invalid Message Format",
    "66": "Version Not Supported",
    "68": "Service Not Supported",
    "72": "System Failure",
    "73": "No Resources Available",
    "93": "APN Access Denied",
}


def analyze_events(events: list[dict]) -> TraceAnalysis:
    errors = []

    for event in events:
        diameter_code = str(event.get("result_code") or event.get("experimental_result_code") or "")
        if diameter_code in DIAMETER_ERROR_CODES:
            errors.append(
                {
                    "frame": event.get("frame"),
                    "severity": "critical",
                    "protocol": "Diameter",
                    "code": diameter_code,
                    "error": DIAMETER_ERROR_CODES[diameter_code],
                    "evidence": f"Diameter failure code {diameter_code} at frame {event.get('frame')}",
                }
            )

        gtp_cause = str(event.get("cause_code") or "")
        if gtp_cause in GTPV2_FAILURE_CAUSES:
            errors.append(
                {
                    "frame": event.get("frame"),
                    "severity": "critical",
                    "protocol": "GTPv2-C",
                    "code": gtp_cause,
                    "error": GTPV2_FAILURE_CAUSES[gtp_cause],
                    "evidence": f"GTPv2-C cause {gtp_cause} at frame {event.get('frame')}",
                }
            )

    ai_context = {
        "trace_summary": {
            "event_count": len(events),
            "error_count": len(errors),
            "protocols": sorted({event.get("protocol") for event in events if event.get("protocol")}),
        },
        "detected_errors": errors[:50],
        "important_events": [
            event
            for event in events
            if event.get("protocol") in {"GTPv2-C", "GTP-U", "Diameter"}
            or event.get("frame") in {err.get("frame") for err in errors}
        ][:100],
        "instruction": "Explain only what is supported by the provided frame evidence. Cite frame numbers.",
    }

    return TraceAnalysis(errors=errors, ai_context=ai_context)
