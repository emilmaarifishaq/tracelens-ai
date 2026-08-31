import json
import subprocess
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from app.models.trace import DecodedTrace
from app.services.raw_gtp import decode_gtp_from_pcap


class DecodeError(RuntimeError):
    pass


def decode_pcaps(paths: list[Path], http2_ports: list[int] | None = None) -> DecodedTrace:
    events = []
    for path in paths:
        decoded = decode_pcap(path, http2_ports=http2_ports)
        for event in decoded.events:
            event["capture_file"] = path.name
            event["original_frame"] = event.get("frame")
            event["frame"] = len(events) + 1
            events.append(event)

    return DecodedTrace(trace_id=uuid4().hex, events=events)


def decode_pcap(path: Path, http2_ports: list[int] | None = None) -> DecodedTrace:
    command = [
        "tshark",
        "-r",
        str(path),
        "-T",
        "json",
    ]
    for port in http2_ports or []:
        command.extend(["-d", f"tcp.port=={port},http2"])

    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
    except FileNotFoundError as exc:
        events = decode_gtp_from_pcap(path)
        if events:
            return DecodedTrace(trace_id=uuid4().hex, events=events)
        raise DecodeError("TShark is not installed or not available in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DecodeError("TShark decode timed out") from exc

    if completed.returncode != 0:
        raise DecodeError(completed.stderr.strip() or "TShark failed to decode the trace")

    try:
        packets = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DecodeError("TShark returned invalid JSON") from exc

    return DecodedTrace(trace_id=uuid4().hex, events=[normalize_packet(packet) for packet in packets])


def normalize_packet(packet: dict) -> dict:
    source = packet.get("_source", {})
    layers = source.get("layers", {})
    frame = layers.get("frame", {})
    ip = layers.get("ip", {})
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})

    protocols = frame.get("frame.protocols", "")
    event = {
        "frame": int(frame.get("frame.number", 0)),
        "time": normalize_time(frame.get("frame.time_epoch")),
        "protocols": protocols,
        "src": ip.get("ip.src"),
        "dst": ip.get("ip.dst"),
        "src_port": tcp.get("tcp.srcport") or udp.get("udp.srcport"),
        "dst_port": tcp.get("tcp.dstport") or udp.get("udp.dstport"),
        "summary": frame.get("frame.protocols", ""),
        "raw_layers": list(layers.keys()),
    }

    if "gtpv2" in layers:
        event.update(normalize_gtpv2(layers["gtpv2"]))

    if "gtp" in layers and "gtpv2" not in layers:
        event.update(normalize_gtpv1(layers["gtp"]))

    if "diameter" in layers:
        event.update(normalize_diameter(layers["diameter"]))

    if "pfcp" in layers:
        event.update(normalize_pfcp(layers["pfcp"]))

    tcp_analysis = tcp.get("tcp.analysis", {})
    if "tcp.analysis.retransmission" in tcp_analysis or "tcp.analysis.fast_retransmission" in tcp_analysis:
        event["is_retransmission"] = True
    if "tcp.analysis.spurious_retransmission" in tcp_analysis:
        event["is_spurious_retransmission"] = True

    return event


def normalize_gtpv2(gtpv2: dict) -> dict:
    message_type = recursive_get(gtpv2, "gtpv2.message_type")
    return {
        "protocol": "GTPv2-C",
        "message": gtp_message_name(message_type),
        "message_type": parse_int(message_type),
        "teid": recursive_get(gtpv2, "gtpv2.teid"),
        "sequence_number": parse_int(recursive_get(gtpv2, "gtpv2.seq")),
        "cause_code": recursive_get(gtpv2, "gtpv2.cause"),
        "imsi": recursive_get(gtpv2, "e212.imsi"),
        "apn": recursive_get(gtpv2, "gtpv2.apn"),
        "response_to": parse_int(recursive_get(gtpv2, "gtpv2.response_to")),
        "response_time_ms": seconds_to_ms(recursive_get(gtpv2, "gtpv2.response_time")),
    }


def normalize_gtpv1(gtp: dict) -> dict:
    message_type = recursive_get(gtp, "gtp.message")
    return {
        "protocol": "GTPv1-C",
        "message": gtp_message_name(message_type),
        "message_type": parse_int(message_type),
        "teid": recursive_get(gtp, "gtp.teid"),
        "sequence_number": parse_int(recursive_get(gtp, "gtp.seq_number")),
        "cause_code": recursive_get(gtp, "gtp.cause"),
        "imsi": recursive_get(gtp, "e212.imsi"),
        "apn": recursive_get(gtp, "gtp.apn"),
    }


def normalize_diameter(diameter: dict) -> dict:
    return {
        "protocol": "Diameter",
        "message": recursive_get(diameter, "diameter.cmd_code"),
        "session_id": recursive_get(diameter, "diameter.Session-Id"),
        "result_code": recursive_get(diameter, "diameter.Result-Code"),
        "experimental_result_code": recursive_get(diameter, "diameter.Experimental-Result-Code"),
        "application_id": recursive_get(diameter, "diameter.applicationId"),
    }


def normalize_pfcp(pfcp: dict) -> dict:
    return {
        "protocol": "PFCP",
        "message": recursive_get(pfcp, "pfcp.msg_type") or recursive_get(pfcp, "pfcp.message_type"),
        "sequence_number": parse_int(recursive_get(pfcp, "pfcp.seq_num")),
        "cause_code": recursive_get(pfcp, "pfcp.cause"),
    }


def recursive_get(value: object, key: str) -> object | None:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = recursive_get(child, key)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = recursive_get(child, key)
            if found is not None:
                return found
    return None


def normalize_time(value: object) -> str | None:
    if value is None:
        return None
    raw = str(value)
    try:
        return str(float(raw))
    except ValueError:
        pass
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return str(datetime.fromisoformat(raw).timestamp())
    except ValueError:
        return str(value)


def parse_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def seconds_to_ms(value: object) -> float | None:
    if value is None:
        return None
    try:
        return round(float(str(value)) * 1000, 3)
    except ValueError:
        return None


def gtp_message_name(value: object) -> str | None:
    message_type = parse_int(value)
    names = {
        16: "Create PDP Context Request",
        17: "Create PDP Context Response",
        18: "Update PDP Context Request",
        19: "Update PDP Context Response",
        20: "Delete PDP Context Request",
        21: "Delete PDP Context Response",
        32: "Create Session Request",
        33: "Create Session Response",
        34: "Modify Bearer Request",
        35: "Modify Bearer Response",
        36: "Delete Session Request",
        37: "Delete Session Response",
        255: "G-PDU",
    }
    return names.get(message_type, str(value) if value is not None else None)
