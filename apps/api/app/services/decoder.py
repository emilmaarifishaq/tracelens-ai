import json
import subprocess
from pathlib import Path
from uuid import uuid4

from app.models.trace import DecodedTrace


class DecodeError(RuntimeError):
    pass


def decode_pcap(path: Path) -> DecodedTrace:
    command = [
        "tshark",
        "-r",
        str(path),
        "-T",
        "json",
    ]

    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=120)
    except FileNotFoundError as exc:
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
        "time": frame.get("frame.time_epoch"),
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

    if "diameter" in layers:
        event.update(normalize_diameter(layers["diameter"]))

    return event


def normalize_gtpv2(gtpv2: dict) -> dict:
    return {
        "protocol": "GTPv2-C",
        "message": gtpv2.get("gtpv2.message_type") or gtpv2.get("gtpv2.message_type_tree", {}).get("gtpv2.message_type"),
        "teid": gtpv2.get("gtpv2.teid"),
        "cause_code": gtpv2.get("gtpv2.cause"),
        "imsi": gtpv2.get("e212.imsi"),
        "apn": gtpv2.get("gtpv2.apn"),
    }


def normalize_diameter(diameter: dict) -> dict:
    return {
        "protocol": "Diameter",
        "message": diameter.get("diameter.cmd_code"),
        "session_id": diameter.get("diameter.Session-Id"),
        "result_code": diameter.get("diameter.Result-Code"),
        "experimental_result_code": diameter.get("diameter.Experimental-Result-Code"),
        "application_id": diameter.get("diameter.applicationId"),
    }
