from pathlib import Path

from app.services.analysis import analyze_events
from app.services.decoder import decode_pcap


REPO_ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    check_gtpv2_failure()
    check_cpe_dns_failure()
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


if __name__ == "__main__":
    main()
