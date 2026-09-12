from urllib.parse import urlparse

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

    errors = sorted(errors, key=error_sort_key)
    error_frames = {err.get("frame") for err in errors}
    participants = build_participants(events, endpoint_mapping)
    procedures = build_procedures(events, error_frames)
    procedure_groups = build_procedure_groups(events, procedures, errors)
    failure_timeline = build_failure_timeline(events, errors)
    host_flows = build_host_flows(events, errors)
    session_drilldowns = build_session_drilldowns(events, host_flows)

    ai_context = {
        "trace_summary": {
            "event_count": len(events),
            "error_count": len(errors),
            "protocols": sorted({event.get("protocol") for event in events if event.get("protocol")}),
            "participants": participants,
            "procedures": procedures,
            "procedure_groups": procedure_groups,
            "failure_timeline": failure_timeline,
            "host_flows": host_flows,
            "session_drilldowns": session_drilldowns,
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


def error_sort_key(error: dict) -> tuple[int, int, int]:
    severity_score = {"critical": 0, "warning": 1, "info": 2}.get(str(error.get("severity")), 3)
    protocol_score = {
        "GTPv2-C": 0,
        "GTPv1-C": 0,
        "Diameter": 1,
        "PFCP": 2,
        "HTTP": 3,
        "SIP": 4,
        "DNS": 5,
        "DHCP": 6,
        "TLS": 7,
        "TCP": 8,
    }.get(str(error.get("protocol")), 9)
    return (severity_score, protocol_score, int(error.get("frame") or 0))


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


def build_failure_timeline(events: list[dict], errors: list[dict]) -> list[dict]:
    errors_by_frame = {error.get("frame"): error for error in errors}
    timeline = []

    for event in events:
        frame = event.get("frame")
        error = errors_by_frame.get(frame)
        reason = timeline_reason(event, error)
        if not reason:
            continue

        timeline.append(
            {
                "frame": frame,
                "time": event.get("time"),
                "severity": error.get("severity") if error else inferred_severity(event),
                "protocol": event.get("protocol"),
                "message": event.get("message"),
                "host": event.get("host"),
                "url": event.get("redirect_url") or event.get("url"),
                "src": event.get("src"),
                "dst": event.get("dst"),
                "reason": reason,
                "evidence": error.get("evidence") if error else timeline_evidence(event, reason),
                "score": timeline_score(event, error),
            }
        )

    return [
        {key: value for key, value in item.items() if key != "score"}
        for item in sorted(
            sorted(timeline, key=lambda item: item["score"], reverse=True)[:50],
            key=lambda item: item.get("frame") or 0,
        )
    ]


def build_host_flows(events: list[dict], errors: list[dict]) -> list[dict]:
    error_frames = {error.get("frame") for error in errors}
    flows: dict[tuple[str, str], dict] = {}

    for event in events:
        host = event_host(event)
        if not host:
            continue

        key = (str(host), str(event.get("protocol") or "-"))
        flow = flows.setdefault(
            key,
            {
                "host": host,
                "protocol": event.get("protocol"),
                "sources": [],
                "destinations": [],
                "first_frame": event.get("frame"),
                "last_frame": event.get("frame"),
                "event_count": 0,
                "issue_count": 0,
                "redirect_count": 0,
                "urls": [],
                "status_codes": [],
            },
        )
        flow["event_count"] += 1
        flow["last_frame"] = event.get("frame")
        if event.get("src") and event.get("src") not in flow["sources"]:
            flow["sources"].append(event.get("src"))
        if event.get("dst") and event.get("dst") not in flow["destinations"]:
            flow["destinations"].append(event.get("dst"))

        url = event.get("redirect_url") or event.get("url")
        if url and url not in flow["urls"]:
            flow["urls"].append(url)
        status_code = event.get("http_status_code") or event.get("sip_status_code") or event.get("dns_response_code")
        if status_code not in {None, "", "0"} and status_code not in flow["status_codes"]:
            flow["status_codes"].append(status_code)
        if event.get("redirect_url"):
            flow["redirect_count"] += 1
        if event.get("frame") in error_frames or inferred_severity(event) in {"warning", "critical"}:
            flow["issue_count"] += 1

    for flow in flows.values():
        if flow["redirect_count"] and flow["issue_count"]:
            flow["status"] = "redirected_with_issues"
        elif flow["redirect_count"]:
            flow["status"] = "redirected"
        elif flow["issue_count"]:
            flow["status"] = "failed"
        else:
            flow["status"] = "observed"
        flow["urls"] = flow["urls"][:3]
        flow["sources"] = flow["sources"][:3]
        flow["destinations"] = flow["destinations"][:3]

    return sorted(
        flows.values(),
        key=lambda flow: (
            0 if flow["status"] in {"redirected", "redirected_with_issues"} else 1 if flow["status"] == "failed" else 2,
            -(flow["issue_count"] + flow["redirect_count"]),
            flow["first_frame"] or 0,
        ),
    )[:30]


def build_session_drilldowns(events: list[dict], host_flows: list[dict]) -> list[dict]:
    drilldowns = []
    for flow in host_flows[:20]:
        matched_events = [
            summarize_session_event(event)
            for event in events
            if event_matches_host_flow(event, flow)
            and event.get("protocol") in {"DNS", "HTTP", "TLS", "QUIC", "TCP", "SIP", "MQTT"}
        ]
        drilldowns.append(
            {
                **flow,
                **build_session_insight(flow, matched_events),
                "events": matched_events[:80],
                "session_event_count": len(matched_events),
            }
        )
    return drilldowns


def event_matches_host_flow(event: dict, flow: dict) -> bool:
    target = str(flow.get("host") or "").lower()
    urls = [str(url).lower() for url in flow.get("urls", []) if url]
    event_values = [
        event.get("host"),
        event.get("url"),
        event.get("redirect_url"),
        event.get("http_host"),
        event.get("http_uri"),
        event.get("http_location"),
        event.get("dns_query"),
        event.get("tls_sni"),
        event.get("quic_sni"),
        event.get("sip_uri"),
    ]
    event_text = " ".join(str(value or "").lower() for value in event_values)
    compact_event_text = event_text.strip()
    if target and target in event_text:
        return True
    if compact_event_text and any(url in event_text or compact_event_text in url for url in urls):
        return True

    endpoint_pool = set(str(address) for address in flow.get("sources", []) + flow.get("destinations", []))
    return is_address_like(target) and (str(event.get("src")) in endpoint_pool or str(event.get("dst")) in endpoint_pool)


def summarize_session_event(event: dict) -> dict:
    return {
        "frame": event.get("frame"),
        "time": event.get("time"),
        "protocol": event.get("protocol"),
        "message": event.get("message") or event.get("protocols"),
        "src": event.get("src"),
        "dst": event.get("dst"),
        "host": event.get("host"),
        "url": event.get("redirect_url") or event.get("url"),
        "dns_query": event.get("dns_query"),
        "http_status_code": event.get("http_status_code"),
        "dns_response_code": event.get("dns_response_code"),
        "tcp_reset": event.get("tcp_reset"),
        "is_retransmission": event.get("is_retransmission"),
        "tls_alert": event.get("tls_alert"),
        "url_inferred": event.get("url_inferred"),
        "evidence": session_event_evidence(event),
    }


def build_session_insight(flow: dict, events: list[dict]) -> dict:
    redirects = sum(1 for event in events if 300 <= (parse_status_code(event.get("http_status_code")) or 0) < 400)
    dns_issues = sum(
        1
        for event in events
        if event.get("protocol") == "DNS" and str(event.get("dns_response_code") or "") not in {"", "0"}
    )
    http_errors = sum(1 for event in events if (parse_status_code(event.get("http_status_code")) or 0) >= 400)
    tcp_issues = sum(1 for event in events if event.get("tcp_reset") or event.get("is_retransmission"))
    tls_issues = sum(1 for event in events if event.get("tls_alert"))
    https_hosts = sum(1 for event in events if event.get("url_inferred"))
    status_codes = unique_values(
        event.get("http_status_code") or event.get("dns_response_code") for event in events
    )[:6]
    target = str(flow.get("host") or "selected target")
    first_frame = flow.get("first_frame") or "-"
    last_frame = flow.get("last_frame") or "-"

    what_happened = " ".join(
        item
        for item in [
            f"{target} was observed in {len(events)} related DNS/HTTP/TLS/TCP events across frames {first_frame} to {last_frame}.",
            f"{redirects} HTTP redirect response{'s' if redirects != 1 else ''} pointed the client to a new URL." if redirects else "",
            f"{http_errors} HTTP error response{'s' if http_errors != 1 else ''} appeared in the same session." if http_errors else "",
            f"{dns_issues} DNS response issue{'s' if dns_issues != 1 else ''} appeared for this target or its related lookup." if dns_issues else "",
            f"{tls_issues} TLS alert{'s' if tls_issues != 1 else ''} appeared after the host was identified." if tls_issues else "",
            f"{tcp_issues} TCP reset/retransmission event{'s' if tcp_issues != 1 else ''} appeared in the path." if tcp_issues else "",
            f"{https_hosts} encrypted HTTPS host observation{'s were' if https_hosts != 1 else ' was'} inferred from TLS/QUIC fields." if https_hosts else "",
            f"Observed status/code values: {', '.join(status_codes)}." if status_codes else "",
        ]
        if item
    )

    likely_cause = (
        "TraceLens did not find an explicit failure for this host; review the surrounding packets for missing responses or unexpected routing."
    )
    if redirects and looks_like_captive_target(target, flow.get("urls", [])):
        likely_cause = "The client traffic is being intercepted by a captive portal or walled-garden policy before normal internet access is allowed."
    elif redirects:
        likely_cause = "The server or gateway is intentionally redirecting the client, so the next troubleshooting point is the Location URL and policy that triggered it."
    elif http_errors:
        likely_cause = "The target service or proxy returned an application-layer error, so the failure is likely above basic IP reachability."
    elif dns_issues:
        likely_cause = "Name resolution failed or returned a non-success response before the application session could complete."
    elif tls_issues:
        likely_cause = "The TCP path reached the encrypted service, but TLS negotiation reported an alert."
    elif tcp_issues:
        likely_cause = "The session shows transport instability, reset, or retransmission before a clean application exchange."

    return {
        "what_happened": what_happened,
        "likely_cause": likely_cause,
        "next_checks": build_session_next_checks(target, redirects, dns_issues, http_errors, tcp_issues, tls_issues),
        "dns_issues": dns_issues,
        "redirects": redirects,
        "http_errors": http_errors,
        "tcp_issues": tcp_issues,
        "tls_issues": tls_issues,
        "https_hosts": https_hosts,
        "session_status_codes": status_codes,
    }


def build_session_next_checks(
    target: str,
    redirects: int,
    dns_issues: int,
    http_errors: int,
    tcp_issues: int,
    tls_issues: int,
) -> list[str]:
    if redirects:
        return [
            f"Open the first redirect frame and verify the Location URL for {target}.",
            "Confirm whether captive portal, proxy, quota, or subscriber policy should redirect this client.",
            "Compare DNS result, original Host header, and redirected host to confirm the access path.",
        ]
    if dns_issues:
        return [
            f"Check DNS server response code and queried name for {target}.",
            "Verify client DNS configuration, resolver reachability, and split-DNS/captive policy.",
            "Look for a later successful DNS answer before judging the application flow.",
        ]
    if http_errors:
        return [
            f"Review HTTP status, Host, URI, and response frame for {target}.",
            "Check proxy, ACS/API endpoint, authentication, and service-side logs for the same timestamp.",
            "Confirm whether the client should receive this status code in the tested scenario.",
        ]
    if tls_issues:
        return [
            f"Check TLS alert frame and SNI/ALPN information for {target}.",
            "Verify certificate, TLS version, cipher compatibility, and middlebox inspection policy.",
            "Correlate with TCP resets or retransmissions near the alert.",
        ]
    if tcp_issues:
        return [
            f"Inspect TCP reset/retransmission frames around {target}.",
            "Check packet loss, firewall resets, asymmetric routing, and MTU/MSS behavior.",
            "Confirm whether the server responds after SYN and whether the session closes cleanly.",
        ]
    return [
        f"Review first and last frames for {target}.",
        "Check whether DNS, TCP setup, TLS host, and application request all appear in order.",
        "Compare this target with a successful target in the same PCAP.",
    ]


def session_event_evidence(event: dict) -> str:
    status = event.get("http_status_code") or event.get("dns_response_code")
    parts = [
        event.get("message") or event.get("protocols"),
        f"code {status}" if status not in {None, ""} else "",
        "TCP reset" if event.get("tcp_reset") else "",
        "retransmission" if event.get("is_retransmission") else "",
        f"TLS alert {event.get('tls_alert')}" if event.get("tls_alert") else "",
    ]
    return " | ".join(str(part) for part in parts if part) or "-"


def unique_values(values: object) -> list[str]:
    unique = []
    for value in values:
        if value not in {None, "", "0"} and str(value) not in unique:
            unique.append(str(value))
    return unique


def is_address_like(value: str) -> bool:
    if not value:
        return False
    return ":" in value or all(part.isdigit() and 0 <= int(part) <= 255 for part in value.split(".")) and value.count(".") == 3


def looks_like_captive_target(target: str, urls: list[str]) -> bool:
    haystack = " ".join([target, *(str(url) for url in urls)]).lower()
    return any(keyword in haystack for keyword in ("captive", "portal", "login", "walled"))


def event_host(event: dict) -> str | None:
    host = event.get("host")
    if host:
        return str(host)
    url = event.get("redirect_url") or event.get("url")
    if url:
        return urlparse(str(url)).netloc or str(url)
    return None


def timeline_reason(event: dict, error: dict | None) -> str | None:
    if error:
        return str(error.get("error") or "Protocol issue")
    protocol = event.get("protocol")
    if event.get("redirect_url"):
        return "HTTP redirect"
    if protocol == "HTTP" and parse_status_code(event.get("http_status_code")) and parse_status_code(event.get("http_status_code")) >= 300:
        return "HTTP status"
    if protocol == "SIP" and parse_status_code(event.get("sip_status_code")) and parse_status_code(event.get("sip_status_code")) >= 300:
        return "SIP status"
    if protocol in {"TLS", "QUIC"} and event.get("url_inferred"):
        return "HTTPS host observed"
    return None


def timeline_evidence(event: dict, reason: str) -> str:
    frame = event.get("frame")
    if event.get("redirect_url"):
        return f"Frame {frame} redirects to {event.get('redirect_url')}."
    if event.get("url_inferred"):
        return f"Frame {frame} shows {event.get('url')} from {event.get('url_source')}."
    return f"Frame {frame} matched {reason}: {event.get('message')}."


def timeline_score(event: dict, error: dict | None) -> int:
    if error:
        severity = error.get("severity")
        return 100 if severity == "critical" else 90 if severity == "warning" else 70
    if event.get("redirect_url"):
        return 95
    protocol = event.get("protocol")
    if protocol == "HTTP" and parse_status_code(event.get("http_status_code")) and parse_status_code(event.get("http_status_code")) >= 400:
        return 88
    if protocol == "SIP" and parse_status_code(event.get("sip_status_code")) and parse_status_code(event.get("sip_status_code")) >= 300:
        return 86
    if protocol == "DNS" and str(event.get("dns_response_code") or "") not in {"", "0"}:
        return 80
    if protocol in {"TLS", "QUIC"} and event.get("url_inferred"):
        return 55
    return 40


def inferred_severity(event: dict) -> str:
    http_code = parse_status_code(event.get("http_status_code"))
    sip_code = parse_status_code(event.get("sip_status_code"))
    dns_code = str(event.get("dns_response_code") or "")
    if http_code and http_code >= 500:
        return "critical"
    if sip_code and sip_code >= 500:
        return "critical"
    if (http_code and http_code >= 400) or (sip_code and sip_code >= 300):
        return "warning"
    if dns_code and dns_code != "0":
        return "warning"
    if event.get("tcp_reset") or event.get("tls_alert"):
        return "warning"
    return "info"


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
