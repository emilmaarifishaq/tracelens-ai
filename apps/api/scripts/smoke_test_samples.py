from pathlib import Path

from app.services.analysis import analyze_events
from app.services.decoder import decode_pcap


REPO_ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    check_gtpv2_failure()
    check_cpe_dns_failure()
    check_local_failure_rules()
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


if __name__ == "__main__":
    main()
