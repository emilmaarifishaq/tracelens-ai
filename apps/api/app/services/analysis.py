from app.models.trace import TraceAnalysis
from app.services.knowledge import load_error_codes, load_procedure_rules


def analyze_events(
    events: list[dict],
    endpoint_mapping: dict[str, dict[str, str]] | None = None,
    settings: dict | None = None,
) -> TraceAnalysis:
    endpoint_mapping = endpoint_mapping or {}
    settings = settings or {}
    events = filter_events(events, settings)
    error_codes = load_error_codes()
    errors = []

    for event in events:
        diameter_code = str(event.get("result_code") or event.get("experimental_result_code") or "")
        diameter_failure = lookup_error(error_codes, "diameter", diameter_code)
        if event.get("protocol") == "Diameter" and diameter_failure:
            errors.append(build_error(event, "Diameter", diameter_code, diameter_failure))

        gtp_cause = str(event.get("cause_code") or "")
        gtp_failure = lookup_error(error_codes, "gtpv2_c", gtp_cause)
        if event.get("protocol") in {"GTPv1-C", "GTPv2-C"} and gtp_failure:
            errors.append(build_error(event, "GTPv2-C", gtp_cause, gtp_failure))

        pfcp_cause = str(event.get("cause_code") or "")
        pfcp_failure = lookup_error(error_codes, "pfcp", pfcp_cause)
        if event.get("protocol") == "PFCP" and pfcp_failure:
            errors.append(build_error(event, "PFCP", pfcp_cause, pfcp_failure))

        dns_code = str(event.get("dns_response_code") or "")
        dns_failure = lookup_error(error_codes, "dns", dns_code)
        if event.get("protocol") == "DNS" and dns_failure:
            errors.append(build_error(event, "DNS", dns_code, dns_failure))

        http_code = str(event.get("http_status_code") or "")
        http_failure = lookup_status_error(error_codes, "http", http_code)
        if event.get("protocol") == "HTTP" and http_failure:
            errors.append(build_error(event, "HTTP", http_code, http_failure))

        sip_code = str(event.get("sip_status_code") or "")
        sip_failure = lookup_status_error(error_codes, "sip", sip_code)
        if event.get("protocol") == "SIP" and sip_failure:
            errors.append(build_error(event, "SIP", sip_code, sip_failure))

        dhcp_type = str(event.get("dhcp_message_type") or "")
        dhcp_failure = lookup_error(error_codes, "dhcp", dhcp_type)
        if event.get("protocol") == "DHCP" and dhcp_failure:
            errors.append(build_error(event, "DHCP", dhcp_type, dhcp_failure))

        tcp_reset = lookup_error(error_codes, "tcp", "RST")
        if event.get("tcp_reset") and tcp_reset:
            errors.append(build_error(event, "TCP", "RST", tcp_reset))

        tls_alert = lookup_error(error_codes, "tls", "alert")
        if event.get("tls_alert") and tls_alert:
            errors.append(build_error(event, "TLS", str(event.get("tls_alert")), tls_alert))

        tcp_retransmission = lookup_error(error_codes, "tcp", "retransmission")
        if event.get("is_retransmission") and tcp_retransmission:
            errors.append(build_error(event, "TCP", "retransmission", tcp_retransmission))

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
            if event.get("protocol")
            in {"GTPv1-C", "GTPv2-C", "GTP-U", "Diameter", "PFCP", "DNS", "DHCP", "HTTP", "SIP", "TLS", "MQTT", "QUIC", "TCP"}
            or event.get("frame") in error_frames
        ][:100],
        "instruction": "Explain only what is supported by the provided frame evidence. Cite frame numbers.",
    }

    return TraceAnalysis(errors=errors, ai_context=ai_context)


def lookup_error(error_codes: dict, domain: str, code: object) -> dict | None:
    if code is None or code == "":
        return None
    return error_codes.get(domain, {}).get(str(code))


def lookup_status_error(error_codes: dict, domain: str, code: object) -> dict | None:
    if code is None or code == "":
        return None
    exact = lookup_error(error_codes, domain, code)
    if exact:
        return exact
    status_code = parse_status_code(code)
    if status_code and status_code >= 400:
        return lookup_error(error_codes, domain, f"{status_code // 100}xx")
    return None


def build_error(event: dict, protocol: str, code: object, definition: dict) -> dict:
    frame = event.get("frame")
    name = definition["name"]
    return {
        "frame": frame,
        "severity": definition.get("severity", "warning"),
        "protocol": protocol,
        "code": str(code),
        "error": name,
        "root_cause": definition.get("root_cause", "TraceLens matched this frame to a local protocol rule."),
        "recommended_checks": definition.get("recommended_checks", []),
        "evidence": build_error_evidence(event, protocol, code, name),
    }


def build_error_evidence(event: dict, protocol: str, code: object, name: str) -> str:
    frame = event.get("frame")
    if protocol == "GTPv2-C":
        message = event.get("message") or "GTPv2-C message"
        return f"{message} returned cause {code} ({name}) at frame {frame}."
    if protocol == "PFCP":
        message = event.get("message") or "PFCP message"
        return f"{message} returned cause {code} ({name}) at frame {frame}."
    if protocol == "Diameter":
        return f"Diameter failure code {code} ({name}) at frame {frame}."
    if protocol == "DNS":
        query = event.get("dns_query") or "query"
        return f"DNS response for {query} returned {name} at frame {frame}."
    if protocol == "HTTP":
        return f"HTTP response {code} ({name}) observed at frame {frame}."
    if protocol == "SIP":
        reason = event.get("sip_reason")
        suffix = f" {reason}" if reason else ""
        return f"SIP response {code}{suffix} ({name}) observed at frame {frame}."
    if protocol == "DHCP":
        requested_ip = event.get("dhcp_requested_ip")
        suffix = f" for requested IP {requested_ip}" if requested_ip else ""
        return f"DHCP message {code} ({name}) observed{suffix} at frame {frame}."
    if protocol == "TCP" and str(code) == "RST":
        return f"TCP RST observed at frame {frame}."
    if protocol == "TCP" and str(code) == "retransmission":
        return f"TCP retransmission detected at frame {frame}."
    if protocol == "TLS":
        return f"TLS alert {code} observed at frame {frame}."
    return f"{protocol} matched local rule {name} at frame {frame}."


def parse_status_code(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


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
    groups = [build_group(rule, events, procedures, errors) for rule in load_procedure_rules()]
    groups = [group for group in groups if group["event_count"] or group["procedure_count"]]

    grouped_frames = {frame for group in groups for frame in group["frames"]}
    ungrouped_control_events = [
        event
        for event in events
        if event.get("frame") not in grouped_frames
        and event.get("protocol") in {"GTPv1-C", "GTPv2-C", "Diameter", "S1AP", "NGAP", "PFCP", "SIP", "DHCP"}
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
