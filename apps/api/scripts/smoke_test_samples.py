from pathlib import Path

from app.services.analysis import analyze_events
from app.services.decoder import decode_pcap, normalize_packet


REPO_ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    check_gtpv2_failure()
    check_cpe_dns_failure()
    check_local_failure_rules()
    check_host_extraction()
    check_http_payload_redirect_extraction()
    print("PASS sample smoke tests")


def check_gtpv2_failure() -> None:
    sample = REPO_ROOT / "samples" / "gtpc-control-plane-failure.pcap"
    if not sample.exists():
        print(
            "SKIP GTPv2-C failure sample: samples/gtpc-control-plane-failure.pcap not found. "
            "This is a local-only fixture (not committed -- *.pcap is gitignored) with a "
            "GTPv2-C Create Session Response, cause 93 (APN Access Denied); "
            "see check_local_failure_rules for an equivalent check that needs no fixture file."
        )
        return

    events = decode_pcap(sample).events
    analysis = analyze_events(events)
    context = analysis.ai_context["trace_summary"]

    assert any(error["error"] == "APN Access Denied" for error in analysis.errors), "missing APN Access Denied"
    assert "GTPv2-C" in context["protocols"], "missing GTPv2-C protocol"
    assert any(group["name"] == "LTE Session Establishment" for group in context["procedure_groups"]), (
        "missing LTE Session Establishment group"
    )
    print("PASS GTPv2-C failure sample")


def check_cpe_dns_failure() -> None:
    sample = REPO_ROOT / "samples" / "cpe" / "prod2.pcap"
    if not sample.exists():
        print("SKIP CPE sample: samples/cpe/prod2.pcap not found")
        return

    events = decode_pcap(sample).events
    analysis = analyze_events(events)
    context = analysis.ai_context["trace_summary"]
    group_names = {group["name"] for group in context["procedure_groups"]}

    assert any(error["error"] == "DNS NXDomain" for error in analysis.errors), "missing DNS NXDomain"
    assert any(event.get("host") for event in events if event.get("protocol") == "DNS"), "missing DNS host extraction"
    assert {"DNS", "TCP", "TLS"}.issubset(set(context["protocols"])), "missing expected CPE protocols"
    assert "CPE Name Resolution" in group_names, "missing CPE Name Resolution group"
    assert "CPE Internet Session" in group_names, "missing CPE Internet Session group"
    print("PASS CPE DNS failure sample")


def check_local_failure_rules() -> None:
    events = [
        {
            "frame": 1,
            "time": "1.0",
            "protocol": "DHCP",
            "message": "DHCP NAK requested 192.0.2.10",
            "dhcp_message_type": "6",
            "dhcp_requested_ip": "192.0.2.10",
        },
        {
            "frame": 2,
            "time": "2.0",
            "protocol": "HTTP",
            "message": "HTTP Response 503",
            "http_status_code": "503",
        },
        {
            "frame": 3,
            "time": "3.0",
            "protocol": "SIP",
            "message": "SIP Response 403 Forbidden",
            "sip_status_code": "403",
            "sip_reason": "Forbidden",
        },
        {
            "frame": 4,
            "time": "4.0",
            "protocol": "PFCP",
            "message": "PFCP Session Establishment Response",
            "cause_code": "65",
            "sequence_number": 10,
        },
        {
            "frame": 5,
            "time": "5.0",
            "protocol": "NGAP",
            "message": "InitialContextSetup Failure",
            "procedure_code": 14,
            "outcome": "unsuccessful",
            "cause_category": "radioNetwork",
            "cause_code": 22,
            "cause_name": "radio-resources-not-available",
        },
        {
            "frame": 6,
            "time": "6.0",
            "protocol": "S1AP",
            "message": "InitialContextSetup Failure",
            "procedure_code": 9,
            "outcome": "unsuccessful",
            "cause_category": "nas",
            "cause_code": 1,
            "cause_name": "authentication-failure",
        },
        {
            "frame": 7,
            "time": "7.0",
            "protocol": "RADIUS",
            "message": "RADIUS Access-Reject",
            "code": "3",
        },
        {
            "frame": 8,
            "time": "8.0",
            "protocol": "NAS-EPS",
            "message": "Authentication failure (MAC failure)",
            "message_type": 92,
            "cause_code": 20,
            "cause_name": "MAC failure",
        },
        {
            "frame": 9,
            "time": "9.0",
            "protocol": "NAS-5GS",
            "message": "Registration reject (Illegal UE)",
            "message_type": 68,
            "cause_code": 3,
            "cause_name": "Illegal UE",
        },
    ]
    analysis = analyze_events(events)
    names = {error["error"] for error in analysis.errors}
    summary = analysis.ai_context["trace_summary"]
    group_names = {group["name"] for group in summary["procedure_groups"]}

    assert "DHCP NAK" in names, "missing DHCP NAK"
    assert "HTTP Service Unavailable" in names, "missing HTTP 503"
    assert "SIP Forbidden" in names, "missing SIP 403"
    assert "PFCP Session Context Not Found" in names, "missing PFCP cause 65"
    assert "radio-resources-not-available" in names, "missing NGAP radioNetwork cause"
    assert "authentication-failure" in names, "missing S1AP nas cause"
    assert "RADIUS Access-Reject" in names, "missing RADIUS Access-Reject"
    assert "MAC failure" in names, "missing NAS-EPS MAC failure"
    assert "Illegal UE" in names, "missing NAS-5GS Illegal UE"
    assert "CPE Address Provisioning" in group_names, "missing DHCP procedure group"
    assert "Application Service Access" in group_names, "missing application access group"
    assert summary["failure_timeline"], "missing failure timeline"
    assert "session_drilldowns" in summary, "missing session drilldowns"
    print("PASS local failure rule coverage")


def check_host_extraction() -> None:
    dns_event = normalize_packet(
        packet(
            10,
            {
                "dns": {
                    "dns.flags.response": "0",
                    "dns.qry.name": "google.com",
                    "dns.qry.type": "1",
                }
            },
        )
    )
    http_event = normalize_packet(
        packet(
            11,
            {
                "tcp": {"tcp.srcport": "12345", "tcp.dstport": "80"},
                "http": {
                    "http.request.method": "GET",
                    "http.host": "example.com",
                    "http.request.uri": "/health",
                },
            },
        )
    )
    tls_event = normalize_packet(
        packet(
            12,
            {
                "tcp": {"tcp.srcport": "12345", "tcp.dstport": "443"},
                "tls": {
                    "tls.handshake.type": "1",
                    "tls.handshake.extensions_server_name": "acs.example.net",
                },
            },
        )
    )
    tls_server_hello = normalize_packet(
        packet(
            16,
            {
                "tcp": {"tcp.srcport": "443", "tcp.dstport": "12345"},
                "tls": {
                    "tls.handshake.type": "2",
                    "tls.handshake.extensions_server_name": "should-not-be-used.example.net",
                },
            },
        )
    )
    quic_event = normalize_packet(
        packet(
            15,
            {
                "udp": {"udp.srcport": "443", "udp.dstport": "12345"},
                "quic": {
                    "quic.long.packet_type": "Initial",
                    "tls.handshake.extensions_server_name": "h3.example.net",
                },
            },
        )
    )
    sip_event = normalize_packet(
        packet(
            13,
            {
                "udp": {"udp.srcport": "5060", "udp.dstport": "5060"},
                "sip": {
                    "sip.Method": "REGISTER",
                    "sip.r-uri": "sip:user@ims.example.org",
                    "sip.Call-ID": "abc123",
                },
            },
        )
    )

    assert dns_event["host"] == "google.com", "missing DNS host"
    assert http_event["host"] == "example.com", "missing HTTP host"
    assert http_event["url"] == "http://example.com/health", "missing HTTP URL"
    assert tls_event["host"] == "acs.example.net", "missing TLS SNI host"
    assert tls_event["url"] == "https://acs.example.net", "missing TLS inferred URL"
    assert tls_event["url_inferred"] is True, "missing TLS inferred marker"
    assert tls_event["tls_client_hello"] is True, "missing TLS Client Hello marker"
    assert tls_server_hello["tls_client_hello"] is False, "wrong TLS Client Hello marker"
    assert tls_server_hello["host"] == "should-not-be-used.example.net", "missing TLS host outside Client Hello"
    assert quic_event["url"] == "https://h3.example.net", "missing QUIC inferred URL"
    assert quic_event["url_source"] == "quic_sni", "missing QUIC URL source"
    assert sip_event["host"] == "ims.example.org", "missing SIP host"
    print("PASS host extraction coverage")


def check_http_payload_redirect_extraction() -> None:
    payload = (
        b"HTTP/1.1 302 Found\r\n"
        b"Server: CaptivePortal\r\n"
        b"Connection: close\r\n"
        b"Location: https://fwa-captive.starliteindonesia.com?bc=nokia\r\n"
        b"\r\n"
    )
    event = normalize_packet(
        packet(
            14,
            {
                "tcp": {
                    "tcp.srcport": "80",
                    "tcp.dstport": "51001",
                    "tcp.payload": payload.hex(":"),
                },
            },
        )
    )

    assert event["protocol"] == "HTTP", "missing HTTP fallback protocol"
    assert event["http_status_code"] == "302", "missing HTTP status from TCP payload"
    assert event["host"] == "fwa-captive.starliteindonesia.com", "missing redirect host"
    assert event["redirect_url"] == "https://fwa-captive.starliteindonesia.com?bc=nokia", "missing redirect URL"
    analysis = analyze_events([event])
    flow = analysis.ai_context["trace_summary"]["host_flows"][0]
    drilldown = analysis.ai_context["trace_summary"]["session_drilldowns"][0]
    assert flow["status"] == "redirected", "HTTP 302 redirect should not be marked failed"
    assert analysis.ai_context["trace_summary"]["failure_timeline"][0]["reason"] == "HTTP redirect", "missing redirect timeline"
    assert drilldown["host"] == "fwa-captive.starliteindonesia.com", "missing captive host drilldown"
    assert "captive portal" in drilldown["likely_cause"].lower(), "missing captive likely cause"
    assert drilldown["events"][0]["frame"] == 14, "missing drilldown event evidence"
    print("PASS HTTP payload redirect extraction")


def packet(frame: int, layers: dict) -> dict:
    merged_layers = {
        "frame": {
            "frame.number": str(frame),
            "frame.time_epoch": str(frame),
            "frame.protocols": ":".join(["eth", "ip", *layers.keys()]),
        },
        "ip": {"ip.src": "192.0.2.1", "ip.dst": "198.51.100.1"},
    }
    merged_layers.update(layers)
    return {"_source": {"layers": merged_layers}}


if __name__ == "__main__":
    main()
