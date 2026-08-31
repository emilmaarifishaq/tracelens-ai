import socket
import struct
import sys
import time
from pathlib import Path


CLIENT_MAC = bytes.fromhex("080042000001")
SERVER_MAC = bytes.fromhex("080042000002")
CLIENT_IP = "1.1.1.1"
SERVER_IP = "2.2.2.2"
CLIENT_PORT = 53001
GTP_C_PORT = 2123
IMSI = "4404440123456789"
APN = "some.node.mnc044.mcc440.3gppnetwork.org"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python samples/make_gtpc_sample.py <output.pcap>")
        return 2

    output = Path(sys.argv[1])
    packets = [
        build_packet(build_gtpv1_create_pdp_context_request()),
        build_packet(build_gtpv2_create_session_request()),
        build_packet(
            build_gtpv2_create_session_response(cause=93),
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_port=GTP_C_PORT,
            dst_port=CLIENT_PORT,
            src_mac=SERVER_MAC,
            dst_mac=CLIENT_MAC,
        ),
    ]

    with output.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = int(time.time())
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", ts, index * 1000, len(packet), len(packet)))
            handle.write(packet)

    return 0


def build_gtpv1_create_pdp_context_request() -> bytes:
    imsi = encode_tbcd(IMSI)
    apn = b"*some.node.mnc044.mcc440.gprs"
    ies = b"\x02" + imsi + b"\x83" + struct.pack("!H", len(apn)) + apn
    header = struct.pack("!BBH", 0x32, 16, len(ies) + 4) + struct.pack("!I", 0xDEADBEEF)
    header += struct.pack("!HBB", 0xCAFE, 0, 0)
    return header + ies


def build_gtpv2_create_session_request() -> bytes:
    imsi = encode_tbcd(IMSI)
    apn = APN.encode("ascii")
    ies = build_gtpv2_ie(1, imsi) + build_gtpv2_ie(71, apn)
    header = struct.pack("!BBH", 0x48, 32, len(ies) + 8)
    header += struct.pack("!I", 0xFFFFFFFF)
    header += bytes.fromhex("dadada00")
    return header + ies


def build_gtpv2_create_session_response(cause: int) -> bytes:
    cause_ie = build_gtpv2_ie(2, bytes([cause, 0]))
    header = struct.pack("!BBH", 0x48, 33, len(cause_ie) + 8)
    header += struct.pack("!I", 0xFFFFFFFF)
    header += bytes.fromhex("dadada00")
    return header + cause_ie


def build_gtpv2_ie(ie_type: int, value: bytes, instance: int = 0) -> bytes:
    return struct.pack("!BH", ie_type, len(value)) + bytes([instance]) + value


def encode_tbcd(digits: str) -> bytes:
    if len(digits) % 2:
        digits += "f"

    encoded = bytearray()
    for index in range(0, len(digits), 2):
        low = int(digits[index], 16)
        high = int(digits[index + 1], 16)
        encoded.append((high << 4) | low)
    return bytes(encoded)


def build_packet(
    gtp_payload: bytes,
    src_ip: str = CLIENT_IP,
    dst_ip: str = SERVER_IP,
    src_port: int = CLIENT_PORT,
    dst_port: int = GTP_C_PORT,
    src_mac: bytes = CLIENT_MAC,
    dst_mac: bytes = SERVER_MAC,
) -> bytes:
    udp_length = 8 + len(gtp_payload)
    ip_total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_length,
        0,
        0,
        64,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    eth_header = dst_mac + src_mac + struct.pack("!H", 0x0800)
    return eth_header + ip_header + udp_header + gtp_payload


if __name__ == "__main__":
    raise SystemExit(main())
