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
    if src_port == 2152 or dst_port == 2152:
        protocol = "GTP-U"
    elif version == 2:
        protocol = "GTPv2-C"
    else:
        protocol = "GTPv1-C"

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

    gtp_header_length = _gtp_header_length(version, flags)
    sequence_number = _gtp_sequence_number(packet, gtp_offset, version, gtp_header_length)
    if sequence_number is not None:
        event["sequence_number"] = sequence_number

    payload_offset = gtp_offset + gtp_header_length
    if protocol == "GTP-U":
        inner = _decode_inner_ipv4(packet, payload_offset)
        if inner:
            event["inner"] = inner
    elif protocol == "GTPv2-C":
        event.update(_decode_gtpv2_ies(packet[payload_offset : gtp_offset + 4 + message_length]))
    else:
        event.update(_decode_gtpv1_ies(packet[payload_offset : gtp_offset + 8 + message_length]))

    return event


def _gtp_header_length(version: int, flags: int) -> int:
    if version == 2:
        return 12 if flags & 0x08 else 8
    return 12 if flags & 0x07 else 8


def _gtp_sequence_number(packet: bytes, gtp_offset: int, version: int, header_length: int) -> int | None:
    if header_length < 12 or len(packet) < gtp_offset + 11:
        return None

    if version == 2:
        return int.from_bytes(packet[gtp_offset + 8 : gtp_offset + 11], "big")

    return int.from_bytes(packet[gtp_offset + 8 : gtp_offset + 10], "big")


def _decode_gtpv1_ies(payload: bytes) -> dict:
    offset = 0
    fields: dict[str, str | list[dict]] = {"information_elements": []}

    while offset < len(payload):
        ie_type = payload[offset]
        offset += 1

        if ie_type == 2 and offset + 8 <= len(payload):
            value = payload[offset : offset + 8]
            offset += 8
            imsi = _decode_tbcd(value)
            fields["imsi"] = imsi
            fields["information_elements"].append({"type": ie_type, "name": "IMSI", "value": imsi})
            continue

        if offset + 2 > len(payload):
            break

        length = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        value = payload[offset : offset + length]
        offset += length

        if ie_type == 131:
            apn = _decode_apn(value)
            fields["apn"] = apn
            fields["information_elements"].append({"type": ie_type, "name": "APN", "value": apn})
        else:
            fields["information_elements"].append({"type": ie_type, "length": length})

    return fields


def _decode_gtpv2_ies(payload: bytes) -> dict:
    offset = 0
    fields: dict[str, str | list[dict]] = {"information_elements": []}

    while offset + 4 <= len(payload):
        ie_type = payload[offset]
        length = struct.unpack("!H", payload[offset + 1 : offset + 3])[0]
        instance = payload[offset + 3] & 0x0F
        offset += 4
        value = payload[offset : offset + length]
        offset += length

        if ie_type == 1:
            imsi = _decode_tbcd(value)
            fields["imsi"] = imsi
            fields["information_elements"].append({"type": ie_type, "name": "IMSI", "instance": instance, "value": imsi})
        elif ie_type == 2 and value:
            cause = str(value[0])
            fields["cause_code"] = cause
            fields["information_elements"].append({"type": ie_type, "name": "Cause", "instance": instance, "value": cause})
        elif ie_type == 71:
            apn = _decode_apn(value)
            fields["apn"] = apn
            fields["information_elements"].append({"type": ie_type, "name": "APN", "instance": instance, "value": apn})
        else:
            fields["information_elements"].append({"type": ie_type, "length": length, "instance": instance})

    return fields


def _decode_tbcd(value: bytes) -> str:
    digits = []
    for byte in value:
        low = byte & 0x0F
        high = byte >> 4
        if low <= 9:
            digits.append(str(low))
        if high <= 9:
            digits.append(str(high))
    return "".join(digits)


def _decode_apn(value: bytes) -> str:
    if not value:
        return ""

    labels = []
    offset = 0
    while offset < len(value):
        label_length = value[offset]
        offset += 1
        if label_length == 0 or offset + label_length > len(value):
            break
        label = value[offset : offset + label_length]
        if any(byte < 32 or byte > 126 for byte in label):
            break
        labels.append(label.decode("ascii"))
        offset += label_length

    if labels and offset == len(value):
        return ".".join(labels)

    return value.decode("ascii", errors="ignore").strip("\x00").lstrip("*")


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
