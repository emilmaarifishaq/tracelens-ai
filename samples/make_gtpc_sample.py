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


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python samples/make_gtpc_sample.py <output.pcap>")
        return 2

    output = Path(sys.argv[1])
    packets = [
        build_packet(build_gtpv1_create_pdp_context_request()),
        build_packet(build_gtpv2_create_session_request()),
    ]

    with output.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = int(time.time())
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", ts, index * 1000, len(packet), len(packet)))
            handle.write(packet)

    return 0


def build_gtpv1_create_pdp_context_request() -> bytes:
    imsi = encode_tbcd("4404440123456789")
    apn = b"*some.node.mnc044.mcc440.gprs"
    ies = b"\x02" + imsi + b"\x83" + struct.pack("!H", len(apn)) + apn
    header = struct.pack("!BBH", 0x32, 16, len(ies) + 4) + struct.pack("!I", 0xDEADBEEF)
    header += struct.pack("!HBB", 0xCAFE, 0, 0)
    return header + ies


def build_gtpv2_create_session_request() -> bytes:
    imsi = encode_tbcd("4404440123456789")
    apn = b"some.node.mnc044.mcc440.3gppnetwork.org"
    ies = build_gtpv2_ie(1, imsi) + build_gtpv2_ie(71, apn)
    header = struct.pack("!BBH", 0x48, 32, len(ies) + 8)
    header += struct.pack("!I", 0xFFFFFFFF)
    header += bytes.fromhex("dadada00")
    return header + ies


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


def build_packet(gtp_payload: bytes) -> bytes:
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
        socket.inet_aton(CLIENT_IP),
        socket.inet_aton(SERVER_IP),
    )
    udp_header = struct.pack("!HHHH", CLIENT_PORT, GTP_C_PORT, udp_length, 0)
    eth_header = SERVER_MAC + CLIENT_MAC + struct.pack("!H", 0x0800)
    return eth_header + ip_header + udp_header + gtp_payload


if __name__ == "__main__":
    raise SystemExit(main())

