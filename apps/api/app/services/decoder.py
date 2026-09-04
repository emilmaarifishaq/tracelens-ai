import json
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
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
    ipv6 = layers.get("ipv6", {})
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})

    protocols = frame.get("frame.protocols", "")
    event = {
        "frame": int(frame.get("frame.number", 0)),
        "time": normalize_time(frame.get("frame.time_epoch")),
        "protocols": protocols,
        "src": ip.get("ip.src") or ipv6.get("ipv6.src"),
        "dst": ip.get("ip.dst") or ipv6.get("ipv6.dst"),
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

    if ("bootp" in layers or "dhcp" in layers) and "protocol" not in event:
        event.update(normalize_dhcp(layers.get("bootp") or layers.get("dhcp") or {}))

    if "dns" in layers and "protocol" not in event:
        event.update(normalize_dns(layers["dns"]))

    if "http" in layers and "protocol" not in event:
        event.update(normalize_http(layers["http"]))

    if "tcp" in layers and "protocol" not in event:
        http_payload = normalize_http_from_tcp(tcp)
        if http_payload:
            event.update(http_payload)

    if "sip" in layers and "protocol" not in event:
        event.update(normalize_sip(layers["sip"]))

    if "tls" in layers and "protocol" not in event:
        event.update(normalize_tls(layers["tls"]))

    if "mqtt" in layers and "protocol" not in event:
        event.update(normalize_mqtt(layers["mqtt"]))

    if "quic" in layers and "protocol" not in event:
        event.update(normalize_quic(layers["quic"]))

    if "ssh" in layers and "protocol" not in event:
        event.update({"protocol": "SSH", "message": "SSH traffic"})

    if "icmp" in layers and "protocol" not in event:
        event.update(normalize_icmp(layers["icmp"]))

    if "icmpv6" in layers and "protocol" not in event:
        event.update({"protocol": "ICMPv6", "message": "ICMPv6 message"})

    if "arp" in layers and "protocol" not in event:
        event.update(normalize_arp(layers["arp"]))

    if "tcp" in layers and "protocol" not in event:
        event.update(normalize_tcp(tcp))

    if "udp" in layers and "protocol" not in event:
        event.update({"protocol": "UDP", "message": f"UDP {event.get('src_port')} -> {event.get('dst_port')}"})

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


def normalize_dns(dns: dict) -> dict:
    is_response = recursive_get(dns, "dns.flags.response") == "1"
    query_name = recursive_get(dns, "dns.qry.name")
    query_type = dns_type_name(recursive_get(dns, "dns.qry.type"))
    response_code = recursive_get(dns, "dns.flags.rcode")
    answer = recursive_get(dns, "dns.a") or recursive_get(dns, "dns.aaaa") or recursive_get(dns, "dns.cname")
    message = "DNS Response" if is_response else "DNS Query"
    if query_name:
        message = f"{message} {query_name}"
    if query_type:
        message = f"{message} {query_type}"
    if answer:
        message = f"{message} -> {answer}"
    if is_response and response_code not in {None, "0"}:
        message = f"{message} ({dns_rcode_name(response_code)})"

    return {
        "protocol": "DNS",
        "message": message,
        "host": query_name,
        "dns_query": query_name,
        "dns_query_type": query_type,
        "dns_response_code": response_code,
        "dns_response": answer,
        "response_to": parse_int(recursive_get(dns, "dns.response_to")),
        "response_time_ms": seconds_to_ms(recursive_get(dns, "dns.time")),
    }


def normalize_http(http: dict) -> dict:
    method = recursive_get(http, "http.request.method")
    host = recursive_get(http, "http.host")
    uri = recursive_get(http, "http.request.uri")
    full_uri = recursive_get(http, "http.request.full_uri")
    status_code = recursive_get(http, "http.response.code")
    location = recursive_get(http, "http.location")
    url = normalize_url(host, uri, full_uri)
    redirect_url = str(location) if location else None
    if method:
        target = url or f"{host or ''}{uri or ''}".strip() or "request"
        message = f"HTTP {method} {target}"
    elif status_code:
        message = f"HTTP Response {status_code}"
        if redirect_url:
            message = f"{message} -> {redirect_url}"
    else:
        message = "HTTP traffic"

    return {
        "protocol": "HTTP",
        "message": message,
        "host": host or host_from_url(redirect_url),
        "url": redirect_url or url,
        "redirect_url": redirect_url,
        "http_location": location,
        "http_method": method,
        "http_host": host,
        "http_uri": uri,
        "http_full_uri": full_uri,
        "http_status_code": status_code,
    }


def normalize_http_from_tcp(tcp: dict) -> dict | None:
    payload = decode_tcp_text(tcp)
    if not payload:
        return None
    lines = payload.splitlines()
    if not lines:
        return None

    first_line = lines[0].strip()
    headers = http_headers(lines[1:])
    host = headers.get("host")
    location = headers.get("location")

    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        status_code = parts[1]
        reason = parts[2] if len(parts) > 2 else ""
        message = f"HTTP Response {status_code}"
        if reason:
            message = f"{message} {reason}"
        if location:
            message = f"{message} -> {location}"
        return {
            "protocol": "HTTP",
            "message": message,
            "host": host or host_from_url(location),
            "url": location,
            "redirect_url": location if status_code.startswith("3") else None,
            "http_location": location,
            "http_status_code": status_code,
            "http_reason": reason,
            "http_from_tcp_payload": True,
        }

    parts = first_line.split(" ", 2)
    if len(parts) >= 2 and parts[0] in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        method = parts[0]
        uri = parts[1]
        url = normalize_url(host, uri, None)
        return {
            "protocol": "HTTP",
            "message": f"HTTP {method} {url or uri}",
            "host": host or host_from_url(uri),
            "url": url,
            "http_method": method,
            "http_host": host,
            "http_uri": uri,
            "http_from_tcp_payload": True,
        }

    return None


def normalize_sip(sip: dict) -> dict:
    method = recursive_get(sip, "sip.Method")
    request_uri = recursive_get(sip, "sip.Request-Line") or recursive_get(sip, "sip.r-uri")
    status_code = recursive_get(sip, "sip.Status-Code") or recursive_get(sip, "sip.status-code")
    reason = recursive_get(sip, "sip.Reason-Phrase") or recursive_get(sip, "sip.reason")
    call_id = recursive_get(sip, "sip.Call-ID") or recursive_get(sip, "sip.call_id")
    host = sip_host(request_uri)

    if status_code:
        message = f"SIP Response {status_code}"
        if reason:
            message = f"{message} {reason}"
    elif method:
        message = f"SIP {method}"
        if request_uri:
            message = f"{message} {request_uri}"
    else:
        message = "SIP traffic"

    return {
        "protocol": "SIP",
        "message": message,
        "host": host,
        "url": request_uri,
        "sip_method": method,
        "sip_status_code": status_code,
        "sip_reason": reason,
        "sip_call_id": call_id,
    }


def normalize_dhcp(dhcp: dict) -> dict:
    message_type = (
        recursive_get(dhcp, "bootp.option.dhcp")
        or recursive_get(dhcp, "bootp.option.dhcp_message_type")
        or recursive_get(dhcp, "dhcp.option.dhcp")
    )
    client_ip = recursive_get(dhcp, "bootp.ip.client")
    your_ip = recursive_get(dhcp, "bootp.ip.your")
    server_ip = recursive_get(dhcp, "bootp.ip.server")
    requested_ip = recursive_get(dhcp, "bootp.option.requested_ip_address")
    hostname = recursive_get(dhcp, "bootp.option.hostname")
    message = f"DHCP {dhcp_message_name(message_type)}"
    if requested_ip:
        message = f"{message} requested {requested_ip}"
    elif your_ip and your_ip != "0.0.0.0":
        message = f"{message} assigned {your_ip}"

    return {
        "protocol": "DHCP",
        "message": message,
        "host": hostname,
        "dhcp_message_type": str(message_type) if message_type is not None else None,
        "dhcp_client_ip": client_ip,
        "dhcp_your_ip": your_ip,
        "dhcp_server_ip": server_ip,
        "dhcp_requested_ip": requested_ip,
        "dhcp_hostname": hostname,
    }


def normalize_tls(tls: dict) -> dict:
    alert = recursive_get(tls, "tls.alert_message.desc") or recursive_get(tls, "tls.alert_message")
    handshake_type = recursive_get(tls, "tls.handshake.type")
    sni = (
        recursive_get(tls, "tls.handshake.extensions_server_name")
        or recursive_get(tls, "tls.handshake.extensions_server_name_list")
    )
    if alert:
        message = f"TLS Alert {alert}"
    elif handshake_type:
        message = f"TLS {tls_handshake_name(handshake_type)}"
        if sni:
            message = f"{message} {sni}"
    else:
        message = "TLS encrypted traffic"

    return {
        "protocol": "TLS",
        "message": message,
        "host": sni,
        "url": inferred_https_url(sni),
        "url_inferred": bool(sni),
        "url_source": "tls_sni" if sni else None,
        "tls_handshake_type": handshake_type,
        "tls_alert": alert,
        "tls_sni": sni,
    }


def normalize_mqtt(mqtt: dict) -> dict:
    message_type = recursive_get(mqtt, "mqtt.msgtype") or recursive_get(mqtt, "mqtt.hdrflags")
    topic = recursive_get(mqtt, "mqtt.topic")
    message = f"MQTT {mqtt_message_name(message_type)}"
    if topic:
        message = f"{message} {topic}"
    return {
        "protocol": "MQTT",
        "message": message,
        "host": topic,
        "mqtt_message_type": message_type,
        "mqtt_topic": topic,
    }


def normalize_quic(quic: dict) -> dict:
    packet_type = recursive_get(quic, "quic.long.packet_type") or recursive_get(quic, "quic.packet_type")
    version = recursive_get(quic, "quic.version")
    sni = recursive_get(quic, "tls.handshake.extensions_server_name")
    message = "QUIC traffic"
    if packet_type:
        message = f"QUIC {packet_type}"
    if sni:
        message = f"{message} {sni}"
    return {
        "protocol": "QUIC",
        "message": message,
        "host": sni,
        "url": inferred_https_url(sni),
        "url_inferred": bool(sni),
        "url_source": "quic_sni" if sni else None,
        "quic_packet_type": packet_type,
        "quic_version": version,
        "quic_sni": sni,
    }


def normalize_icmp(icmp: dict) -> dict:
    icmp_type = recursive_get(icmp, "icmp.type")
    icmp_code = recursive_get(icmp, "icmp.code")
    return {
        "protocol": "ICMP",
        "message": icmp_message_name(icmp_type, icmp_code),
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
    }


def normalize_arp(arp: dict) -> dict:
    opcode = recursive_get(arp, "arp.opcode")
    src = recursive_get(arp, "arp.src.proto_ipv4")
    dst = recursive_get(arp, "arp.dst.proto_ipv4")
    return {
        "protocol": "ARP",
        "message": f"ARP {arp_opcode_name(opcode)} {src or ''} -> {dst or ''}".strip(),
        "arp_opcode": opcode,
    }


def normalize_tcp(tcp: dict) -> dict:
    flags = tcp_flags(tcp)
    stream = recursive_get(tcp, "tcp.stream")
    message = f"TCP {flags}" if flags else "TCP segment"
    if stream is not None:
        message = f"{message} stream {stream}"
    return {
        "protocol": "TCP",
        "message": message,
        "tcp_flags": flags,
        "tcp_stream": stream,
        "tcp_reset": recursive_get(tcp, "tcp.flags.reset") == "1",
    }


def normalize_url(host: object, uri: object, full_uri: object) -> str | None:
    if full_uri:
        return str(full_uri)
    if not host and not uri:
        return None
    if uri and str(uri).startswith(("http://", "https://")):
        return str(uri)
    if host and uri:
        return f"http://{host}{uri}"
    if host:
        return str(host)
    return str(uri)


def host_from_url(value: object) -> str | None:
    if not value:
        return None
    parsed = urlparse(str(value))
    return parsed.netloc or None


def inferred_https_url(host: object) -> str | None:
    if not host:
        return None
    return f"https://{host}"


def decode_tcp_text(tcp: dict) -> str | None:
    payload = recursive_get(tcp, "tcp.payload") or recursive_get(tcp, "tcp.segment_data")
    if not payload:
        return None
    raw_hex = str(payload).replace(":", "")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if not raw.startswith((b"HTTP/", b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")):
        return None
    try:
        return raw.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None


def http_headers(lines: list[str]) -> dict[str, str]:
    headers = {}
    for line in lines:
        if not line.strip():
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def sip_host(uri: object) -> str | None:
    if not uri:
        return None
    value = str(uri)
    if value.startswith("sip:"):
        value = value[4:]
    if value.startswith("sips:"):
        value = value[5:]
    if "@" in value:
        value = value.split("@", 1)[1]
    for separator in [";", "?", " "]:
        value = value.split(separator, 1)[0]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value or None


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


def dns_type_name(value: object) -> str | None:
    query_type = parse_int(value)
    names = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        35: "NAPTR",
        65: "HTTPS",
    }
    return names.get(query_type, str(value) if value is not None else None)


def dns_rcode_name(value: object) -> str:
    code = parse_int(value)
    names = {
        0: "NoError",
        1: "FormErr",
        2: "ServFail",
        3: "NXDomain",
        4: "NotImp",
        5: "Refused",
    }
    return names.get(code, f"rcode {value}")


def tls_handshake_name(value: object) -> str:
    handshake_type = parse_int(value)
    names = {
        1: "Client Hello",
        2: "Server Hello",
        4: "New Session Ticket",
        8: "Encrypted Extensions",
        11: "Certificate",
        13: "Certificate Request",
        14: "Server Hello Done",
        15: "Certificate Verify",
        16: "Client Key Exchange",
        20: "Finished",
    }
    return names.get(handshake_type, f"Handshake {value}")


def mqtt_message_name(value: object) -> str:
    message_type = parse_int(value)
    names = {
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        8: "SUBSCRIBE",
        9: "SUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
    }
    return names.get(message_type, f"message {value}" if value is not None else "traffic")


def dhcp_message_name(value: object) -> str:
    message_type = parse_int(value)
    names = {
        1: "Discover",
        2: "Offer",
        3: "Request",
        4: "Decline",
        5: "ACK",
        6: "NAK",
        7: "Release",
        8: "Inform",
    }
    return names.get(message_type, f"message {value}" if value is not None else "traffic")


def icmp_message_name(icmp_type: object, icmp_code: object) -> str:
    message_type = parse_int(icmp_type)
    names = {
        0: "ICMP Echo Reply",
        3: "ICMP Destination Unreachable",
        5: "ICMP Redirect",
        8: "ICMP Echo Request",
        11: "ICMP Time Exceeded",
    }
    message = names.get(message_type, f"ICMP type {icmp_type}")
    if icmp_code not in {None, "0", 0}:
        message = f"{message} code {icmp_code}"
    return message


def arp_opcode_name(value: object) -> str:
    opcode = parse_int(value)
    names = {
        1: "Request",
        2: "Reply",
    }
    return names.get(opcode, f"opcode {value}")


def tcp_flags(tcp: dict) -> str:
    names = []
    for key, label in [
        ("tcp.flags.syn", "SYN"),
        ("tcp.flags.ack", "ACK"),
        ("tcp.flags.fin", "FIN"),
        ("tcp.flags.reset", "RST"),
        ("tcp.flags.push", "PSH"),
    ]:
        if recursive_get(tcp, key) == "1":
            names.append(label)
    return "+".join(names)


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
