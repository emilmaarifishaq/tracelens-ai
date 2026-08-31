import socket
import struct
from pathlib import Path


GTP_MESSAGE_TYPES = {
    1: "Echo Request",
    2: "Echo Response",
    16: "Create PDP Context Request",
    17: "Create PDP Context Response",
    18: "Update PDP Context Request",
    19: "Update PDP Context Response",
    20: "Delete PDP Context Request",
    21: "Delete PDP Context Response",
    26: "Error Indication",
    31: "Supported Extension Headers Notification",
    32: "Create Session Request",
    33: "Create Session Response",
    34: "Modify Bearer Request",
    35: "Modify Bearer Response",
    36: "Delete Session Request",
    37: "Delete Session Response",
    255: "G-PDU",
}


def decode_gtp_from_pcap(path: Path) -> list[dict]:
    data = path.read_bytes()
    if len(data) < 24:
        return []

    endian = _pcap_endian(data[:4])
    if endian is None:
        return []

    offset = 24
    frame = 0
    events = []

    while offset + 16 <= len(data):
        frame += 1
        packet_header = data[offset : offset + 16]
        offset += 16
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
        packet = data[offset : offset + incl_len]
        offset += incl_len

        event = _decode_gtp_packet(packet)
        if event:
            event["frame"] = frame
            event["time"] = f"{ts_sec}.{ts_usec:06d}"
            events.append(event)

    return events


def _pcap_endian(magic: bytes) -> str | None:
    if magic == b"\xd4\xc3\xb2\xa1":
        return "<"
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">"
    return None


def _decode_gtp_packet(packet: bytes) -> dict | None:
    if len(packet) < 14:
        return None

    eth_type = struct.unpack("!H", packet[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_offset = 14
    if len(packet) < ip_offset + 20:
        return None

    version_ihl = packet[ip_offset]
    ihl = (version_ihl & 0x0F) * 4
    protocol = packet[ip_offset + 9]
    if protocol != 17:
        return None

    src = socket.inet_ntoa(packet[ip_offset + 12 : ip_offset + 16])
    dst = socket.inet_ntoa(packet[ip_offset + 16 : ip_offset + 20])
    udp_offset = ip_offset + ihl
    if len(packet) < udp_offset + 8:
        return None

    src_port, dst_port, udp_len, _checksum = struct.unpack("!HHHH", packet[udp_offset : udp_offset + 8])
    if src_port not in {2123, 2152, 3386} and dst_port not in {2123, 2152, 3386}:
        return None

    gtp_offset = udp_offset + 8
    if len(packet) < gtp_offset + 8:
        return None

    flags, message_type, message_length = struct.unpack("!BBH", packet[gtp_offset : gtp_offset + 4])
    version = flags >> 5
    teid = struct.unpack("!I", packet[gtp_offset + 4 : gtp_offset + 8])[0]
    protocol = "GTP-U" if src_port == 2152 or dst_port == 2152 else "GTP-C"

    event = {
        "protocol": protocol,
        "message": GTP_MESSAGE_TYPES.get(message_type, f"Message Type {message_type}"),
        "message_type": message_type,
        "message_length": message_length,
        "gtp_version": version,
        "teid": f"0x{teid:08x}",
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocols": "eth:ip:udp:gtp",
        "raw_layers": ["eth", "ip", "udp", "gtp"],
    }

    gtp_header_length = 12 if flags & 0x07 else 8
    inner = _decode_inner_ipv4(packet, gtp_offset + gtp_header_length)
    if inner:
        event["inner"] = inner

    return event


def _decode_inner_ipv4(packet: bytes, offset: int) -> dict | None:
    if len(packet) < offset + 20:
        return None

    version = packet[offset] >> 4
    if version != 4:
        return None

    ihl = (packet[offset] & 0x0F) * 4
    if ihl < 20 or len(packet) < offset + ihl:
        return None

    protocol_number = packet[offset + 9]
    return {
        "src": socket.inet_ntoa(packet[offset + 12 : offset + 16]),
        "dst": socket.inet_ntoa(packet[offset + 16 : offset + 20]),
        "protocol": _ip_protocol_name(protocol_number),
        "protocol_number": protocol_number,
    }


def _ip_protocol_name(protocol_number: int) -> str:
    if protocol_number == 1:
        return "ICMP"
    if protocol_number == 6:
        return "TCP"
    if protocol_number == 17:
        return "UDP"
    return f"IP protocol {protocol_number}"
