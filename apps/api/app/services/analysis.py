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


def analyze_events(
    events: list[dict],
    endpoint_mapping: dict[str, dict[str, str]] | None = None,
    settings: dict | None = None,
) -> TraceAnalysis:
    endpoint_mapping = endpoint_mapping or {}
    settings = settings or {}
    events = filter_events(events, settings)
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

    error_frames = {err.get("frame") for err in errors}
    participants = build_participants(events, endpoint_mapping)
    procedures = build_procedures(events, error_frames)
    procedure_groups = build_procedure_groups(events, procedures, errors)

    ai_context = {
        "trace_summary": {
            "event_count": len(events),
            "error_count": len(errors),
            "protocols": sorted({event.get("protocol") for event in events if event.get("protocol")}),
            "participants": participants,
            "procedures": procedures,
            "procedure_groups": procedure_groups,
            "endpoint_mapping_count": len(endpoint_mapping),
        },
        "events": events,
        "detected_errors": errors[:50],
        "important_events": [
            event
            for event in events
            if event.get("protocol") in {"GTPv1-C", "GTPv2-C", "GTP-U", "Diameter"}
            or event.get("frame") in error_frames
        ][:100],
        "instruction": "Explain only what is supported by the provided frame evidence. Cite frame numbers.",
    }

    return TraceAnalysis(errors=errors, ai_context=ai_context)


PROCEDURE_GROUP_RULES = [
    {
        "name": "LTE Attach",
        "technology": "4G",
        "keywords": ["Attach", "Authentication", "Security Mode", "Initial Context", "Initial UE"],
        "protocols": ["S1AP", "Diameter"],
    },
    {
        "name": "LTE Session Establishment",
        "technology": "4G",
        "keywords": ["Create Session", "Create Bearer", "Modify Bearer", "Create PDP Context"],
        "protocols": ["GTPv1-C", "GTPv2-C"],
    },
    {
        "name": "LTE Detach",
        "technology": "4G",
        "keywords": ["Detach", "Delete Session", "Delete Bearer", "Delete PDP Context"],
        "protocols": ["S1AP", "GTPv1-C", "GTPv2-C"],
    },
    {
        "name": "5G Registration",
        "technology": "5G",
        "keywords": ["Registration", "Authentication", "Security Mode", "Initial UE"],
        "protocols": ["NGAP", "HTTP/2"],
    },
    {
        "name": "5G PDU Session",
        "technology": "5G",
        "keywords": ["PDU Session", "PFCP Session", "Nsmf", "Namf"],
        "protocols": ["NGAP", "PFCP", "HTTP/2"],
    },
    {
        "name": "IMS Registration",
        "technology": "IMS",
        "keywords": ["REGISTER", "SIP", "IMS", "P-CSCF"],
        "protocols": ["SIP"],
    },
]


def filter_events(events: list[dict], settings: dict) -> list[dict]:
    show_heartbeats = bool(settings.get("show_heartbeats", False))
    hide_duplicate_pfcp = bool(settings.get("hide_duplicate_pfcp", True))
    filtered = []
    seen_pfcp = set()

    for event in events:
        message = str(event.get("message") or "")
        if not show_heartbeats and message in {"Echo Request", "Echo Response", "Heartbeat Request", "Heartbeat Response"}:
            continue

        if hide_duplicate_pfcp and event.get("protocol") == "PFCP":
            signature = (
                event.get("src"),
                event.get("dst"),
                event.get("message"),
                event.get("sequence_number"),
                event.get("cause_code"),
            )
            if signature in seen_pfcp:
                continue
            seen_pfcp.add(signature)

        filtered.append(event)

    return filtered


def build_procedure_groups(events: list[dict], procedures: list[dict], errors: list[dict]) -> list[dict]:
    groups = [build_group(rule, events, procedures, errors) for rule in PROCEDURE_GROUP_RULES]
    groups = [group for group in groups if group["event_count"] or group["procedure_count"]]

    grouped_frames = {frame for group in groups for frame in group["frames"]}
    ungrouped_control_events = [
        event
        for event in events
        if event.get("frame") not in grouped_frames
        and event.get("protocol") in {"GTPv1-C", "GTPv2-C", "Diameter", "S1AP", "NGAP", "PFCP", "SIP"}
    ]
    if ungrouped_control_events:
        groups.append(
            {
                "name": "Other Control Signaling",
                "technology": "Network",
                "status": "failed" if any_error_in_frames(errors, {event.get("frame") for event in ungrouped_control_events}) else "ok",
                "start_frame": ungrouped_control_events[0].get("frame"),
                "end_frame": ungrouped_control_events[-1].get("frame"),
                "duration_ms": duration_between(ungrouped_control_events[0].get("time"), ungrouped_control_events[-1].get("time")),
                "event_count": len(ungrouped_control_events),
                "procedure_count": 0,
                "frames": [event.get("frame") for event in ungrouped_control_events],
                "protocols": sorted({event.get("protocol") for event in ungrouped_control_events if event.get("protocol")}),
                "summary": "Control-plane signaling not matched to a known telecom procedure yet.",
            }
        )

    return sorted(groups, key=lambda group: group.get("start_frame") or 0)


def build_group(rule: dict, events: list[dict], procedures: list[dict], errors: list[dict]) -> dict:
    matched_events = [event for event in events if matches_rule(event, rule)]
    matched_procedures = [procedure for procedure in procedures if matches_rule(procedure, rule)]
    frames = sorted(
        {
            value
            for item in matched_events
            for value in [item.get("frame")]
            if value is not None
        }
        | {
            value
            for procedure in matched_procedures
            for value in [procedure.get("request_frame"), procedure.get("response_frame")]
            if value is not None
        }
    )
    start_frame = frames[0] if frames else None
    end_frame = frames[-1] if frames else None
    first_event = first_event_for_frame(events, start_frame)
    last_event = first_event_for_frame(events, end_frame)
    failed = any(procedure.get("status") == "failed" for procedure in matched_procedures) or any_error_in_frames(
        errors, set(frames)
    )

    return {
        "name": rule["name"],
        "technology": rule["technology"],
        "status": "failed" if failed else "ok",
        "start_frame": start_frame,
        "end_frame": end_frame,
        "duration_ms": duration_between(first_event.get("time") if first_event else None, last_event.get("time") if last_event else None),
        "event_count": len(matched_events),
        "procedure_count": len(matched_procedures),
        "frames": frames,
        "protocols": sorted({event.get("protocol") for event in matched_events if event.get("protocol")}),
        "summary": group_summary(rule["name"], failed, matched_procedures, matched_events),
    }


def matches_rule(item: dict, rule: dict) -> bool:
    protocols = rule.get("protocols", [])
    item_protocol = str(item.get("protocol") or "")
    item_protocols = str(item.get("protocols") or "")
    if protocols and item_protocol not in protocols and not any(protocol.lower() in item_protocols.lower() for protocol in protocols):
        return False

    text = " ".join(
        str(item.get(key) or "") for key in ("message", "procedure", "protocol", "protocols", "summary")
    ).lower()
    return any(keyword.lower() in text for keyword in rule["keywords"])


def any_error_in_frames(errors: list[dict], frames: set) -> bool:
    return any(error.get("frame") in frames for error in errors)


def first_event_for_frame(events: list[dict], frame: object) -> dict | None:
    for event in events:
        if event.get("frame") == frame:
            return event
    return None


def group_summary(name: str, failed: bool, procedures: list[dict], events: list[dict]) -> str:
    if procedures:
        status = "failed" if failed else "completed"
        return f"{name} {status} across {len(procedures)} request/response procedure."
    if events:
        status = "has a detected failure" if failed else "has decoded signaling events"
        return f"{name} {status}, but no complete request/response pair was matched yet."
    return f"{name} was not observed in this trace."


def build_participants(events: list[dict], endpoint_mapping: dict[str, dict[str, str]]) -> list[dict]:
    addresses = []
    for event in events:
        for key in ("src", "dst"):
            address = event.get(key)
            if isinstance(address, str) and address not in addresses:
                addresses.append(address)

    participants = []
    for index, address in enumerate(addresses):
        mapped = endpoint_mapping.get(address, {})
        participants.append(
            {
                "address": address,
                "label": mapped.get("label") or infer_participant_label(address, index),
                "namespace": mapped.get("namespace", ""),
                "source": mapped.get("source", "inferred"),
            }
        )

    return participants


def infer_participant_label(address: str, index: int) -> str:
    if address.startswith("1."):
        return "Access / UE side"
    if address.startswith("2."):
        return "Packet core node"
    if address.startswith("192.168."):
        return f"Lab node {index + 1}"
    return address


def build_procedures(events: list[dict], error_frames: set) -> list[dict]:
    procedures = []
    requests: dict[tuple[str, int | str | None], dict] = {}

    for event in events:
        message = str(event.get("message") or "")
        key = (str(event.get("protocol") or ""), event.get("sequence_number") or event.get("teid"))

        if message.endswith("Request"):
            requests[key] = event
            continue

        if message.endswith("Response") and key in requests:
            request = requests[key]
            duration_ms = duration_between(request.get("time"), event.get("time"))
            procedures.append(
                {
                    "request_frame": request.get("frame"),
                    "response_frame": event.get("frame"),
                    "protocol": event.get("protocol"),
                    "procedure": message.replace(" Response", ""),
                    "duration_ms": duration_ms,
                    "status": "failed" if event.get("frame") in error_frames else "ok",
                }
            )

    return procedures


def duration_between(start: object, end: object) -> float | None:
    try:
        return round((float(end) - float(start)) * 1000, 3)
    except (TypeError, ValueError):
        return None
