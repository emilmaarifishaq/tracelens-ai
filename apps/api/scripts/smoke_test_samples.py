from pathlib import Path

from app.services.analysis import analyze_events
from app.services.decoder import decode_pcap, normalize_packet


REPO_ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    check_gtpv2_failure()
    check_cpe_dns_failure()
    check_local_failure_rules()
    check_host_extraction()
    print("PASS sample smoke tests")


def check_gtpv2_failure() -> None:
    sample = REPO_ROOT / "samples" / "gtpc-control-plane-failure.pcap"
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
    ]
    analysis = analyze_events(events)
    names = {error["error"] for error in analysis.errors}
    group_names = {group["name"] for group in analysis.ai_context["trace_summary"]["procedure_groups"]}

    assert "DHCP NAK" in names, "missing DHCP NAK"
    assert "HTTP Service Unavailable" in names, "missing HTTP 503"
    assert "SIP Forbidden" in names, "missing SIP 403"
    assert "PFCP Session Context Not Found" in names, "missing PFCP cause 65"
    assert "CPE Address Provisioning" in group_names, "missing DHCP procedure group"
    assert "Application Service Access" in group_names, "missing application access group"
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
    assert sip_event["host"] == "ims.example.org", "missing SIP host"
    print("PASS host extraction coverage")


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
