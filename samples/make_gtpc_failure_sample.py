#!/usr/bin/env python3
"""
Generate a GTPv2-C Create Session failure PCAP.
Scenario: MME → SGW → PGW session creation with failure response.
Failure: PGW returns "User Authentication Failed" (cause 3)
"""
import socket
import struct
import sys
import time
from pathlib import Path


CLIENT_MAC = bytes.fromhex("080042000001")  # MME
SERVER_MAC = bytes.fromhex("080042000002")  # SGW
CLIENT_IP = "192.168.1.10"      # MME
SERVER_IP = "192.168.1.20"      # SGW
PGW_IP = "192.168.2.20"         # PGW
CLIENT_PORT = 40000
GTPC_PORT = 2123


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python samples/make_gtpc_failure_sample.py <output.pcap>")
        return 2

    output = Path(sys.argv[1])

    packets = [
        # 1. MME → SGW: Create Session Request
        build_packet(
            build_gtpv2_create_session_request(),
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_port=CLIENT_PORT,
            dst_port=GTPC_PORT,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
        ),

        # 2. SGW → PGW: Create Session Request (forwarded)
        build_packet(
            build_gtpv2_create_session_request(teid=0x11111111),
            src_ip=SERVER_IP,
            dst_ip=PGW_IP,
            src_port=GTPC_PORT,
            dst_port=GTPC_PORT,
            src_mac=SERVER_MAC,
            dst_mac=bytes.fromhex("080042000003"),
        ),

        # 3. PGW → SGW: Create Session Response - FAILURE
        # Cause: 3 = User Authentication Failed
        build_packet(
            build_gtpv2_create_session_response(
                teid=0x11111111,
                cause=3,  # User Authentication Failed
                failure=True
            ),
            src_ip=PGW_IP,
            dst_ip=SERVER_IP,
            src_port=GTPC_PORT,
            dst_port=GTPC_PORT,
            src_mac=bytes.fromhex("080042000003"),
            dst_mac=SERVER_MAC,
        ),

        # 4. SGW → MME: Create Session Response - FAILURE (forwarded)
        build_packet(
            build_gtpv2_create_session_response(
                teid=0x99999999,
                cause=3,  # User Authentication Failed
                failure=True
            ),
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_port=GTPC_PORT,
            dst_port=CLIENT_PORT,
            src_mac=SERVER_MAC,
            dst_mac=CLIENT_MAC,
        ),

        # 5. MME → SGW: Delete Session Request (cleanup)
        build_packet(
            build_gtpv2_delete_session_request(teid=0x99999999),
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_port=CLIENT_PORT,
            dst_port=GTPC_PORT,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
        ),
    ]

    # Write PCAP file
    with output.open("wb") as handle:
        # PCAP global header
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        ts = int(time.time())
        for index, packet in enumerate(packets):
            # PCAP packet header
            handle.write(struct.pack("<IIII", ts, index * 100000, len(packet), len(packet)))
            handle.write(packet)

    print(f"✓ Generated GTPv2-C failure PCAP: {output}")
    print(f"  Size: {output.stat().st_size} bytes")
    print(f"  Scenario: Create Session Failure (User Authentication Failed)")
    print(f"  Packets: {len(packets)}")
    return 0


def build_gtpv2_create_session_request(teid: int = 0xFFFFFFFF) -> bytes:
    """Build GTPv2-C Create Session Request"""
    # IMSI IE (type 1)
    imsi = encode_tbcd("4404440123456789")
    imsi_ie = build_gtpv2_ie(1, imsi)

    # APN IE (type 71)
    apn = b"internet"
    apn_ie = build_gtpv2_ie(71, apn)

    # Sender F-TEID IE (type 86)
    sender_fteid = struct.pack("!BHI", 0x80, 5, teid)
    sender_fteid_ie = build_gtpv2_ie(86, sender_fteid)

    ies = imsi_ie + apn_ie + sender_fteid_ie

    # GTPv2-C header
    # Version: 2, Piggyback: 0, TEID flag: 1, Message type: 32 (Create Session Request)
    header = struct.pack("!BBH", 0x48, 32, len(ies) + 8)
    header += struct.pack("!I", teid)  # TEID
    header += bytes.fromhex("00000001")  # Sequence number

    return header + ies


def build_gtpv2_create_session_response(
    teid: int = 0xFFFFFFFF,
    cause: int = 16,  # Request accepted
    failure: bool = False
) -> bytes:
    """Build GTPv2-C Create Session Response"""

    # Cause IE (type 2) - with failure flag
    cause_ie_value = struct.pack("!BB", cause, 0)
    if failure:
        cause_ie_value = struct.pack("!BB", cause, 0)  # Set failure bit
    cause_ie = build_gtpv2_ie(2, cause_ie_value)

    ies = cause_ie

    # GTPv2-C header
    # Message type: 33 (Create Session Response)
    header = struct.pack("!BBH", 0x48, 33, len(ies) + 8)
    header += struct.pack("!I", teid)  # TEID
    header += bytes.fromhex("00000002")  # Sequence number

    return header + ies


def build_gtpv2_delete_session_request(teid: int) -> bytes:
    """Build GTPv2-C Delete Session Request"""

    # Cause IE (type 2) - Normal release
    cause_ie = build_gtpv2_ie(2, struct.pack("!BB", 19, 0))

    ies = cause_ie

    # GTPv2-C header
    # Message type: 36 (Delete Session Request)
    header = struct.pack("!BBH", 0x48, 36, len(ies) + 8)
    header += struct.pack("!I", teid)
    header += bytes.fromhex("00000003")  # Sequence number

    return header + ies


def build_gtpv2_ie(ie_type: int, value: bytes, instance: int = 0) -> bytes:
    """Build GTPv2-C Information Element"""
    return struct.pack("!BH", ie_type, len(value)) + bytes([instance]) + value


def encode_tbcd(digits: str) -> bytes:
    """Encode digits as TBCD (Telephony Binary Coded Decimal)"""
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
    dst_port: int = GTPC_PORT,
    src_mac: bytes = CLIENT_MAC,
    dst_mac: bytes = SERVER_MAC,
) -> bytes:
    """Build complete packet: Ethernet + IP + UDP + GTP payload"""

    # UDP layer
    udp_length = 8 + len(gtp_payload)
    ip_total_length = 20 + udp_length

    # IP header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version + IHL
        0,     # DSCP
        ip_total_length,
        0,     # ID
        0,     # Flags + Fragment offset
        64,    # TTL
        17,    # Protocol (UDP)
        0,     # Checksum (set to 0 for simplicity)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # UDP header
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)

    # Ethernet header
    eth_header = dst_mac + src_mac + struct.pack("!H", 0x0800)

    return eth_header + ip_header + udp_header + gtp_payload


if __name__ == "__main__":
    raise SystemExit(main())
