from app.models.trace import TraceAnalysis


DIAMETER_ERROR_CODES = {
    "5001": "DIAMETER_ERROR_USER_UNKNOWN",
    "5003": "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
    "5004": "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
    "5005": "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
}

GTPV2_FAILURE_CAUSES = {
    "64": {
        "name": "Context Not Found",
        "root_cause": "The peer could not find the referenced session or tunnel context.",
        "recommended_checks": [
            "Check TEID and sequence correlation against earlier session messages.",
            "Confirm the session was not already deleted or timed out.",
            "Inspect peer node logs around the reported frame.",
        ],
    },
    "65": {
        "name": "Invalid Message Format",
        "root_cause": "The peer rejected the message because mandatory fields or encoding are invalid.",
        "recommended_checks": [
            "Validate the request IE layout against 3GPP expectations.",
            "Check vendor interop issues or malformed optional IEs.",
        ],
    },
    "66": {
        "name": "Version Not Supported",
        "root_cause": "The peer does not support the received GTP protocol version.",
        "recommended_checks": [
            "Verify interface protocol version configuration on both peers.",
            "Check whether traffic is reaching the intended node.",
        ],
    },
    "68": {
        "name": "Service Not Supported",
        "root_cause": "The receiving node does not support the requested service or procedure.",
        "recommended_checks": [
            "Confirm the target node supports the requested procedure.",
            "Check node role and interface routing.",
        ],
    },
    "72": {
        "name": "System Failure",
        "root_cause": "The receiving node reported an internal system failure.",
        "recommended_checks": [
            "Check node health, overload, and application logs.",
            "Verify whether the failure is repeated for other subscribers.",
            "Inspect alarms around the trace timestamp.",
        ],
    },
    "73": {
        "name": "No Resources Available",
        "root_cause": "The receiving node could not allocate required resources for the session.",
        "recommended_checks": [
            "Check capacity, license, and pool utilization on the peer node.",
            "Verify whether the condition affects one APN/DNN or all traffic.",
        ],
    },
    "93": {
        "name": "APN Access Denied",
        "root_cause": "The subscriber or network policy does not allow access to the requested APN.",
        "recommended_checks": [
            "Verify the subscriber APN profile in HSS/UDM.",
            "Check APN spelling and APN/DNN selection in the request.",
            "Review roaming restrictions and policy-control response for this subscriber.",
        ],
    },
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
            failure = GTPV2_FAILURE_CAUSES[gtp_cause]
            errors.append(
                {
                    "frame": event.get("frame"),
                    "severity": "critical",
                    "protocol": "GTPv2-C",
                    "code": gtp_cause,
                    "error": failure["name"],
                    "root_cause": failure["root_cause"],
                    "recommended_checks": failure["recommended_checks"],
                    "evidence": (
                        f"{event.get('message', 'GTPv2-C message')} returned cause {gtp_cause} "
                        f"({failure['name']}) at frame {event.get('frame')}"
                    ),
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
            if event.get("protocol") in {"GTPv1-C", "GTPv2-C", "GTP-U", "Diameter"}
            or event.get("frame") in {err.get("frame") for err in errors}
        ][:100],
        "instruction": "Explain only what is supported by the provided frame evidence. Cite frame numbers.",
    }

    return TraceAnalysis(errors=errors, ai_context=ai_context)
