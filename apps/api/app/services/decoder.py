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


def decode_pcaps(
    paths: list[Path], http2_ports: list[int] | None = None, keylog_path: Path | None = None
) -> DecodedTrace:
    events = []
    warnings = []
    for path in paths:
        decoded = decode_pcap(path, http2_ports=http2_ports, keylog_path=keylog_path)
        for event in decoded.events:
            event["capture_file"] = path.name
            event["original_frame"] = event.get("frame")
            event["frame"] = len(events) + 1
            events.append(event)
        warnings.extend(decoded.warnings)

    return DecodedTrace(trace_id=uuid4().hex, events=events, warnings=warnings)


def decode_pcap(
    path: Path, http2_ports: list[int] | None = None, keylog_path: Path | None = None
) -> DecodedTrace:
    command = [
        "tshark",
        "-r",
        str(path),
        "-T",
        "json",
        "--no-duplicate-keys",
    ]
    for port in http2_ports or []:
        command.extend(["-d", f"tcp.port=={port},http2"])
    if keylog_path is not None:
        command.extend(["-o", f"tls.keylog_file:{keylog_path}"])

    try:
        # Large real-world captures (tens of MB, hundreds of thousands of frames)
        # can legitimately take tshark well past a minute to dissect, especially on
        # machines with heavy antivirus/endpoint-protection I/O overhead. 120s was
        # cutting off decodes that would otherwise succeed; give it more room.
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=600)
    except FileNotFoundError as exc:
        events = decode_gtp_from_pcap(path)
        if events:
            return DecodedTrace(trace_id=uuid4().hex, events=events)
        raise DecodeError("TShark is not installed or not available in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DecodeError("TShark decode timed out") from exc

    warnings = []
    if completed.returncode != 0:
        # tshark can exit non-zero (e.g. 14) on a truncated/corrupted capture --
        # common when a capture app is killed or a device disconnects mid-capture --
        # while still emitting a complete, valid JSON array covering every frame
        # decoded before the corruption point. Only treat this as fatal if there's
        # no usable output to fall back on; otherwise surface it as a warning so the
        # user still gets to see and analyze the frames that decoded successfully.
        if not completed.stdout.strip():
            raise DecodeError(completed.stderr.strip() or "TShark failed to decode the trace")
        warnings.append(
            f"Capture file appears truncated or corrupted: {completed.stderr.strip()}"
        )

    try:
        packets = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        if warnings:
            raise DecodeError(warnings[0]) from exc
        raise DecodeError("TShark returned invalid JSON") from exc

    return DecodedTrace(
        trace_id=uuid4().hex,
        events=[normalize_packet(packet) for packet in packets],
        warnings=warnings,
    )


def first_layer(value: object) -> dict:
    """Some frames carry more than one instance of a layer (e.g. the inner and outer
    IP header of a GTP-encapsulated packet). --no-duplicate-keys turns those into a
    list instead of silently dropping all but one; take the first (outermost) one for
    top-level frame identification."""
    if isinstance(value, list):
        return value[0] if value and isinstance(value[0], dict) else {}
    if isinstance(value, dict):
        return value
    return {}


def normalize_packet(packet: dict) -> dict:
    source = packet.get("_source", {})
    layers = source.get("layers", {})
    frame = first_layer(layers.get("frame", {}))
    ip = first_layer(layers.get("ip", {}))
    ipv6 = first_layer(layers.get("ipv6", {}))
    tcp = first_layer(layers.get("tcp", {}))
    udp = first_layer(layers.get("udp", {}))

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

    if "ngap" in layers and "protocol" not in event:
        event.update(normalize_ngap(layers["ngap"]))

    if "s1ap" in layers and "protocol" not in event:
        event.update(normalize_s1ap(layers["s1ap"]))

    if "sctp" in layers and "protocol" not in event:
        event.update(normalize_sctp(layers["sctp"]))

    if "snmp" in layers and "protocol" not in event:
        event.update(normalize_snmp(layers["snmp"]))

    if "radius" in layers and "protocol" not in event:
        event.update(normalize_radius(layers["radius"]))

    if "ldap" in layers and "protocol" not in event:
        event.update(normalize_ldap(layers["ldap"]))

    if "ntp" in layers and "protocol" not in event:
        event.update(normalize_ntp(layers["ntp"]))

    if "smtp" in layers and "protocol" not in event:
        event.update(normalize_smtp(layers["smtp"]))

    if "pop" in layers and "protocol" not in event:
        event.update(normalize_pop(layers["pop"]))

    if "imap" in layers and "protocol" not in event:
        event.update(normalize_imap(layers["imap"]))

    if "bgp" in layers and "protocol" not in event:
        event.update(normalize_bgp(layers["bgp"]))

    if "ospf" in layers and "protocol" not in event:
        event.update(normalize_ospf(layers["ospf"]))

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
        "message": recursive_get(diameter, "diameter.cmd.code"),
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
    is_client_hello = parse_int(handshake_type) == 1
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
        "tls_client_hello": is_client_hello,
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


# ========== Additional Protocol Normalizers ==========

# NGAP/S1AP procedure and Cause value tables below are generated directly
# from `tshark -G values`, i.e. the same authoritative enumerations the
# ngap/s1ap dissectors themselves use (3GPP TS 38.413 / TS 36.413 Cause and
# ProcedureCode IEs) -- not hand-transcribed from spec text.

NGAP_PROCEDURE_NAMES = {
    0: "id-AMFConfigurationUpdate", 1: "id-AMFStatusIndication", 2: "id-CellTrafficTrace",
    3: "id-DeactivateTrace", 4: "id-DownlinkNASTransport", 5: "id-DownlinkNonUEAssociatedNRPPaTransport",
    6: "id-DownlinkRANConfigurationTransfer", 7: "id-DownlinkRANStatusTransfer",
    8: "id-DownlinkUEAssociatedNRPPaTransport", 9: "id-ErrorIndication", 10: "id-HandoverCancel",
    11: "id-HandoverNotification", 12: "id-HandoverPreparation", 13: "id-HandoverResourceAllocation",
    14: "id-InitialContextSetup", 15: "id-InitialUEMessage", 16: "id-LocationReportingControl",
    17: "id-LocationReportingFailureIndication", 18: "id-LocationReport", 19: "id-NASNonDeliveryIndication",
    20: "id-NGReset", 21: "id-NGSetup", 22: "id-OverloadStart", 23: "id-OverloadStop", 24: "id-Paging",
    25: "id-PathSwitchRequest", 26: "id-PDUSessionResourceModify", 27: "id-PDUSessionResourceModifyIndication",
    28: "id-PDUSessionResourceRelease", 29: "id-PDUSessionResourceSetup", 30: "id-PDUSessionResourceNotify",
    31: "id-PrivateMessage", 32: "id-PWSCancel", 33: "id-PWSFailureIndication", 34: "id-PWSRestartIndication",
    35: "id-RANConfigurationUpdate", 36: "id-RerouteNASRequest", 37: "id-RRCInactiveTransitionReport",
    38: "id-TraceFailureIndication", 39: "id-TraceStart", 40: "id-UEContextModification",
    41: "id-UEContextRelease", 42: "id-UEContextReleaseRequest", 43: "id-UERadioCapabilityCheck",
    44: "id-UERadioCapabilityInfoIndication", 45: "id-UETNLABindingRelease", 46: "id-UplinkNASTransport",
    47: "id-UplinkNonUEAssociatedNRPPaTransport", 48: "id-UplinkRANConfigurationTransfer",
    49: "id-UplinkRANStatusTransfer", 50: "id-UplinkUEAssociatedNRPPaTransport", 51: "id-WriteReplaceWarning",
    52: "id-SecondaryRATDataUsageReport", 53: "id-UplinkRIMInformationTransfer",
    54: "id-DownlinkRIMInformationTransfer", 55: "id-RetrieveUEInformation", 56: "id-UEInformationTransfer",
    57: "id-RANCPRelocationIndication", 58: "id-UEContextResume", 59: "id-UEContextSuspend",
    60: "id-UERadioCapabilityIDMapping", 61: "id-HandoverSuccess", 62: "id-UplinkRANEarlyStatusTransfer",
    63: "id-DownlinkRANEarlyStatusTransfer", 64: "id-AMFCPRelocationIndication",
    65: "id-ConnectionEstablishmentIndication", 66: "id-BroadcastSessionModification",
    67: "id-BroadcastSessionRelease", 68: "id-BroadcastSessionSetup", 69: "id-DistributionSetup",
    70: "id-DistributionRelease", 71: "id-MulticastSessionActivation", 72: "id-MulticastSessionDeactivation",
    73: "id-MulticastSessionUpdate", 74: "id-MulticastGroupPaging", 75: "id-BroadcastSessionReleaseRequired",
    76: "id-TimingSynchronisationStatus", 77: "id-TimingSynchronisationStatusReport",
    78: "id-MTCommunicationHandling", 79: "id-RANPagingRequest", 80: "id-BroadcastSessionTransport",
}

NGAP_RADIONETWORK_CAUSE = {
    0: "unspecified", 1: "txnrelocoverall-expiry", 2: "successful-handover",
    3: "release-due-to-ngran-generated-reason", 4: "release-due-to-5gc-generated-reason",
    5: "handover-cancelled", 6: "partial-handover", 7: "ho-failure-in-target-5GC-ngran-node-or-target-system",
    8: "ho-target-not-allowed", 9: "tngrelocoverall-expiry", 10: "tngrelocprep-expiry",
    11: "cell-not-available", 12: "unknown-targetID", 13: "no-radio-resources-available-in-target-cell",
    14: "unknown-local-UE-NGAP-ID", 15: "inconsistent-remote-UE-NGAP-ID",
    16: "handover-desirable-for-radio-reason", 17: "time-critical-handover",
    18: "resource-optimisation-handover", 19: "reduce-load-in-serving-cell", 20: "user-inactivity",
    21: "radio-connection-with-ue-lost", 22: "radio-resources-not-available", 23: "invalid-qos-combination",
    24: "failure-in-radio-interface-procedure", 25: "interaction-with-other-procedure",
    26: "unknown-PDU-session-ID", 27: "unkown-qos-flow-ID", 28: "multiple-PDU-session-ID-instances",
    29: "multiple-qos-flow-ID-instances", 30: "encryption-and-or-integrity-protection-algorithms-not-supported",
    31: "ng-intra-system-handover-triggered", 32: "ng-inter-system-handover-triggered",
    33: "xn-handover-triggered", 34: "not-supported-5QI-value", 35: "ue-context-transfer",
    36: "ims-voice-eps-fallback-or-rat-fallback-triggered", 37: "up-integrity-protection-not-possible",
    38: "up-confidentiality-protection-not-possible", 39: "slice-not-supported",
    40: "ue-in-rrc-inactive-state-not-reachable", 41: "redirection",
    42: "resources-not-available-for-the-slice", 43: "ue-max-integrity-protected-data-rate-reason",
    44: "release-due-to-cn-detected-mobility", 45: "n26-interface-not-available",
    46: "release-due-to-pre-emption", 47: "multiple-location-reporting-reference-ID-instances",
    48: "rsn-not-available-for-the-up", 49: "npn-access-denied", 50: "cag-only-access-denied",
    51: "insufficient-ue-capabilities", 52: "redcap-ue-not-supported", 53: "unknown-MBS-Session-ID",
    54: "indicated-MBS-session-area-information-not-served-by-the-gNB",
    55: "inconsistent-slice-info-for-the-session", 56: "misaligned-association-for-multicast-unicast",
    57: "eredcap-ue-not-supported", 58: "two-rx-xr-ue-not-supported",
}

NGAP_TRANSPORT_CAUSE = {0: "transport-resource-unavailable", 1: "unspecified"}

NGAP_NAS_CAUSE = {
    0: "normal-release", 1: "authentication-failure", 2: "deregister", 3: "unspecified",
    4: "uE-not-in-PLMN-serving-area", 5: "mobile-IAB-not-authorized", 6: "iAB-not-authorized",
}

NGAP_PROTOCOL_CAUSE = {
    0: "transfer-syntax-error", 1: "abstract-syntax-error-reject",
    2: "abstract-syntax-error-ignore-and-notify", 3: "message-not-compatible-with-receiver-state",
    4: "semantic-error", 5: "abstract-syntax-error-falsely-constructed-message", 6: "unspecified",
}

NGAP_MISC_CAUSE = {
    0: "control-processing-overload", 1: "not-enough-user-plane-processing-resources",
    2: "hardware-failure", 3: "om-intervention", 4: "unknown-PLMN-or-SNPN", 5: "unspecified",
}

NGAP_CAUSE_TABLES = {
    "radioNetwork": NGAP_RADIONETWORK_CAUSE,
    "transport": NGAP_TRANSPORT_CAUSE,
    "nas": NGAP_NAS_CAUSE,
    "protocol": NGAP_PROTOCOL_CAUSE,
    "misc": NGAP_MISC_CAUSE,
}

S1AP_PROCEDURE_NAMES = {
    0: "id-HandoverPreparation", 1: "id-HandoverResourceAllocation", 2: "id-HandoverNotification",
    3: "id-PathSwitchRequest", 4: "id-HandoverCancel", 5: "id-E-RABSetup", 6: "id-E-RABModify",
    7: "id-E-RABRelease", 8: "id-E-RABReleaseIndication", 9: "id-InitialContextSetup", 10: "id-Paging",
    11: "id-downlinkNASTransport", 12: "id-initialUEMessage", 13: "id-uplinkNASTransport", 14: "id-Reset",
    15: "id-ErrorIndication", 16: "id-NASNonDeliveryIndication", 17: "id-S1Setup",
    18: "id-UEContextReleaseRequest", 19: "id-DownlinkS1cdma2000tunnelling",
    20: "id-UplinkS1cdma2000tunnelling", 21: "id-UEContextModification", 22: "id-UECapabilityInfoIndication",
    23: "id-UEContextRelease", 24: "id-eNBStatusTransfer", 25: "id-MMEStatusTransfer",
    26: "id-DeactivateTrace", 27: "id-TraceStart", 28: "id-TraceFailureIndication",
    29: "id-ENBConfigurationUpdate", 30: "id-MMEConfigurationUpdate", 31: "id-LocationReportingControl",
    32: "id-LocationReportingFailureIndication", 33: "id-LocationReport", 34: "id-OverloadStart",
    35: "id-OverloadStop", 36: "id-WriteReplaceWarning", 37: "id-eNBDirectInformationTransfer",
    38: "id-MMEDirectInformationTransfer", 39: "id-PrivateMessage", 40: "id-eNBConfigurationTransfer",
    41: "id-MMEConfigurationTransfer", 42: "id-CellTrafficTrace", 43: "id-Kill",
    44: "id-downlinkUEAssociatedLPPaTransport", 45: "id-uplinkUEAssociatedLPPaTransport",
    46: "id-downlinkNonUEAssociatedLPPaTransport", 47: "id-uplinkNonUEAssociatedLPPaTransport",
    48: "id-UERadioCapabilityMatch", 49: "id-PWSRestartIndication", 50: "id-E-RABModificationIndication",
    51: "id-PWSFailureIndication", 52: "id-RerouteNASRequest", 53: "id-UEContextModificationIndication",
    54: "id-ConnectionEstablishmentIndication", 55: "id-UEContextSuspend", 56: "id-UEContextResume",
    57: "id-NASDeliveryIndication", 58: "id-RetrieveUEInformation", 59: "id-UEInformationTransfer",
    60: "id-eNBCPRelocationIndication", 61: "id-MMECPRelocationIndication",
    62: "id-SecondaryRATDataUsageReport", 63: "id-UERadioCapabilityIDMapping", 64: "id-HandoverSuccess",
    65: "id-eNBEarlyStatusTransfer", 66: "id-MMEEarlyStatusTransfer",
}

S1AP_RADIONETWORK_CAUSE = {
    0: "unspecified", 1: "tx2relocoverall-expiry", 2: "successful-handover",
    3: "release-due-to-eutran-generated-reason", 4: "handover-cancelled", 5: "partial-handover",
    6: "ho-failure-in-target-EPC-eNB-or-target-system", 7: "ho-target-not-allowed",
    8: "tS1relocoverall-expiry", 9: "tS1relocprep-expiry", 10: "cell-not-available",
    11: "unknown-targetID", 12: "no-radio-resources-available-in-target-cell",
    13: "unknown-mme-ue-s1ap-id", 14: "unknown-enb-ue-s1ap-id", 15: "unknown-pair-ue-s1ap-id",
    16: "handover-desirable-for-radio-reason", 17: "time-critical-handover",
    18: "resource-optimisation-handover", 19: "reduce-load-in-serving-cell", 20: "user-inactivity",
    21: "radio-connection-with-ue-lost", 22: "load-balancing-tau-required", 23: "cs-fallback-triggered",
    24: "ue-not-available-for-ps-service", 25: "radio-resources-not-available",
    26: "failure-in-radio-interface-procedure", 27: "invalid-qos-combination",
    28: "interrat-redirection", 29: "interaction-with-other-procedure", 30: "unknown-E-RAB-ID",
    31: "multiple-E-RAB-ID-instances", 32: "encryption-and-or-integrity-protection-algorithms-not-supported",
    33: "s1-intra-system-handover-triggered", 34: "s1-inter-system-handover-triggered",
    35: "x2-handover-triggered", 36: "redirection-towards-1xRTT", 37: "not-supported-QCI-value",
    38: "invalid-CSG-Id", 39: "release-due-to-pre-emption", 40: "n26-interface-not-available",
    41: "insufficient-ue-capabilities", 42: "maximum-bearer-pre-emption-rate-exceeded",
    43: "up-integrity-protection-not-possible", 44: "release-due-to-discontinuous-coverage",
}

S1AP_TRANSPORT_CAUSE = {0: "transport-resource-unavailable", 1: "unspecified"}

S1AP_NAS_CAUSE = {
    0: "normal-release", 1: "authentication-failure", 2: "detach", 3: "unspecified",
    4: "csg-subscription-expiry", 5: "uE-not-in-PLMN-serving-area", 6: "iab-not-authorized",
}

S1AP_PROTOCOL_CAUSE = {
    0: "transfer-syntax-error", 1: "abstract-syntax-error-reject",
    2: "abstract-syntax-error-ignore-and-notify", 3: "message-not-compatible-with-receiver-state",
    4: "semantic-error", 5: "abstract-syntax-error-falsely-constructed-message", 6: "unspecified",
}

S1AP_MISC_CAUSE = {
    0: "control-processing-overload", 1: "not-enough-user-plane-processing-resources",
    2: "hardware-failure", 3: "om-intervention", 4: "unspecified", 5: "unknown-PLMN",
}

S1AP_CAUSE_TABLES = {
    "radioNetwork": S1AP_RADIONETWORK_CAUSE,
    "transport": S1AP_TRANSPORT_CAUSE,
    "nas": S1AP_NAS_CAUSE,
    "protocol": S1AP_PROTOCOL_CAUSE,
    "misc": S1AP_MISC_CAUSE,
}


def outcome_type(value: object, prefix: str) -> str | None:
    """NGAP/S1AP PDUs are an ASN.1 CHOICE of initiatingMessage,
    successfulOutcome, or unsuccessfulOutcome -- which one is present (as a
    dict key, not a field value) determines whether a given procedure code
    is a request, a success response, or a reject/failure response."""
    if isinstance(value, dict):
        if f"{prefix}.initiatingMessage_element" in value:
            return "initiating"
        if f"{prefix}.successfulOutcome_element" in value:
            return "successful"
        if f"{prefix}.unsuccessfulOutcome_element" in value:
            return "unsuccessful"
        for child in value.values():
            found = outcome_type(child, prefix)
            if found:
                return found
    if isinstance(value, list):
        for child in value:
            found = outcome_type(child, prefix)
            if found:
                return found
    return None


def extract_ran_cause(value: dict, prefix: str) -> tuple[str, int] | None:
    """NGAP/S1AP represent Cause as a CHOICE across 5 categories
    (radioNetwork/transport/nas/protocol/misc); only one is present per
    message. Returns (category, numeric value) or None if no Cause IE."""
    for category in ("radioNetwork", "transport", "nas", "protocol", "misc"):
        found = recursive_get(value, f"{prefix}.{category}")
        if found is not None:
            return category, parse_int(found)
    return None


def normalize_ngap(ngap: dict) -> dict:
    procedure_code = parse_int(recursive_get(ngap, "ngap.procedureCode"))
    outcome = outcome_type(ngap, "ngap")
    cause = extract_ran_cause(ngap, "ngap")
    procedure_name = NGAP_PROCEDURE_NAMES.get(procedure_code, f"procedure {procedure_code}")
    message = ngap_s1ap_message_name(procedure_name, outcome)

    event: dict = {
        "protocol": "NGAP",
        "message": message,
        "procedure_code": procedure_code,
        "outcome": outcome,
    }
    if cause:
        category, code = cause
        event["cause_category"] = category
        event["cause_code"] = code
        event["cause_name"] = NGAP_CAUSE_TABLES[category].get(code, str(code))
        event["message"] = f"{message} ({event['cause_name']})"
    return event


def normalize_s1ap(s1ap: dict) -> dict:
    procedure_code = parse_int(recursive_get(s1ap, "s1ap.procedureCode"))
    outcome = outcome_type(s1ap, "s1ap")
    cause = extract_ran_cause(s1ap, "s1ap")
    procedure_name = S1AP_PROCEDURE_NAMES.get(procedure_code, f"procedure {procedure_code}")
    message = ngap_s1ap_message_name(procedure_name, outcome)

    event: dict = {
        "protocol": "S1AP",
        "message": message,
        "procedure_code": procedure_code,
        "outcome": outcome,
    }
    if cause:
        category, code = cause
        event["cause_category"] = category
        event["cause_code"] = code
        event["cause_name"] = S1AP_CAUSE_TABLES[category].get(code, str(code))
        event["message"] = f"{message} ({event['cause_name']})"
    return event


def ngap_s1ap_message_name(procedure_name: str, outcome: str | None) -> str:
    # e.g. "id-NGSetup" -> "NGSetup". Not every procedure has a paired
    # request/response (e.g. InitialUEMessage, ErrorIndication are
    # initiatingMessage-only), so label the outcome plainly rather than
    # guessing a "Request"/"Response" suffix that would be wrong for those.
    name = procedure_name[3:] if procedure_name.startswith("id-") else procedure_name
    suffix = {"initiating": "", "successful": " Response", "unsuccessful": " Failure"}.get(outcome, "")
    return f"{name}{suffix}"


def normalize_sctp(sctp: dict) -> dict:
    chunk_type = recursive_get(sctp, "sctp.chunk_type")
    verification_tag = recursive_get(sctp, "sctp.verification_tag")
    message = f"SCTP {sctp_chunk_name(chunk_type)}" if chunk_type else "SCTP traffic"
    return {
        "protocol": "SCTP",
        "message": message,
        "chunk_type": chunk_type,
        "verification_tag": verification_tag,
    }


def normalize_snmp(snmp: dict) -> dict:
    pdu_type = recursive_get(snmp, "snmp.pdutype")
    community = recursive_get(snmp, "snmp.community")
    oid = recursive_get(snmp, "snmp.oid")
    message = f"SNMP {snmp_pdu_name(pdu_type)}"
    if oid:
        message = f"{message} {oid}"
    return {
        "protocol": "SNMP",
        "message": message,
        "pdu_type": pdu_type,
        "community": community,
        "oid": oid,
    }


def normalize_radius(radius: dict) -> dict:
    code = recursive_get(radius, "radius.code")
    identifier = recursive_get(radius, "radius.id")
    username = recursive_get(radius, "radius.username")
    message = f"RADIUS {radius_code_name(code)}"
    if username:
        message = f"{message} {username}"
    return {
        "protocol": "RADIUS",
        "message": message,
        "code": code,
        "identifier": identifier,
        "username": username,
    }


def normalize_ldap(ldap: dict) -> dict:
    message_type = recursive_get(ldap, "ldap.messageType")
    protocol_op = recursive_get(ldap, "ldap.protocolOp")
    dn = recursive_get(ldap, "ldap.dn")
    message = f"LDAP {ldap_message_name(message_type)}"
    if dn:
        message = f"{message} {dn}"
    return {
        "protocol": "LDAP",
        "message": message,
        "message_type": message_type,
        "protocol_op": protocol_op,
        "dn": dn,
    }


def normalize_ntp(ntp: dict) -> dict:
    mode = recursive_get(ntp, "ntp.mode")
    version = recursive_get(ntp, "ntp.version")
    leap = recursive_get(ntp, "ntp.flags.leap")
    message = f"NTP {ntp_mode_name(mode)}"
    return {
        "protocol": "NTP",
        "message": message,
        "mode": mode,
        "version": version,
        "leap": leap,
    }


def normalize_smtp(smtp: dict) -> dict:
    command = recursive_get(smtp, "smtp.command")
    response_code = recursive_get(smtp, "smtp.response_code")
    message = f"SMTP {'Response' if response_code else 'Command'}"
    if command:
        message = f"{message} {command}"
    if response_code:
        message = f"{message} {response_code}"
    return {
        "protocol": "SMTP",
        "message": message,
        "command": command,
        "response_code": response_code,
    }


def normalize_pop(pop: dict) -> dict:
    command = recursive_get(pop, "pop.command")
    response = recursive_get(pop, "pop.response")
    message = f"POP {'Response' if response else 'Command'}"
    if command:
        message = f"{message} {command}"
    return {
        "protocol": "POP3",
        "message": message,
        "command": command,
        "response": response,
    }


def normalize_imap(imap: dict) -> dict:
    command = recursive_get(imap, "imap.command")
    response = recursive_get(imap, "imap.response")
    message = f"IMAP {'Response' if response else 'Command'}"
    if command:
        message = f"{message} {command}"
    return {
        "protocol": "IMAP",
        "message": message,
        "command": command,
        "response": response,
    }


def normalize_bgp(bgp: dict) -> dict:
    msg_type = recursive_get(bgp, "bgp.type")
    marker = recursive_get(bgp, "bgp.marker")
    return {
        "protocol": "BGP",
        "message": f"BGP {bgp_message_name(msg_type)}",
        "message_type": msg_type,
        "marker": marker,
    }


def normalize_ospf(ospf: dict) -> dict:
    msg_type = recursive_get(ospf, "ospf.msg_type")
    router_id = recursive_get(ospf, "ospf.routerid")
    area_id = recursive_get(ospf, "ospf.areaid")
    return {
        "protocol": "OSPF",
        "message": f"OSPF {ospf_message_name(msg_type)}",
        "message_type": msg_type,
        "router_id": router_id,
        "area_id": area_id,
    }


# ========== Protocol Message Name Helpers ==========

def sctp_chunk_name(value: object) -> str:
    chunk_type = parse_int(value)
    names = {
        0: "DATA",
        1: "INIT",
        2: "INIT-ACK",
        3: "SACK",
        4: "HEARTBEAT",
        5: "HEARTBEAT-ACK",
        6: "ABORT",
        7: "SHUTDOWN",
        8: "SHUTDOWN-ACK",
        9: "ERROR",
        10: "COOKIE-ECHO",
        11: "COOKIE-ACK",
        12: "ECNE",
        13: "CWR",
        14: "SHUTDOWN-COMPLETE",
    }
    return names.get(chunk_type, f"chunk {value}" if value is not None else "traffic")


def snmp_pdu_name(value: object) -> str:
    pdu_type = parse_int(value)
    names = {
        0: "GetRequest",
        1: "GetNextRequest",
        2: "GetResponse",
        3: "SetRequest",
        4: "Trap",
        5: "GetBulkRequest",
        6: "InformRequest",
        7: "SNMPv2-Trap",
    }
    return names.get(pdu_type, f"PDU {value}" if value is not None else "traffic")


def radius_code_name(value: object) -> str:
    code = parse_int(value)
    names = {
        1: "Access-Request",
        2: "Access-Accept",
        3: "Access-Reject",
        4: "Accounting-Request",
        5: "Accounting-Response",
        11: "Access-Challenge",
        40: "Disconnect-Request",
        41: "Disconnect-ACK",
        42: "Disconnect-NAK",
        43: "CoA-Request",
        44: "CoA-ACK",
        45: "CoA-NAK",
    }
    return names.get(code, f"Code {value}" if value is not None else "traffic")


def ldap_message_name(value: object) -> str:
    msg_type = parse_int(value)
    names = {
        0: "BindRequest",
        1: "BindResponse",
        2: "UnbindRequest",
        3: "SearchRequest",
        4: "SearchResultEntry",
        5: "SearchResultDone",
        6: "ModifyRequest",
        7: "ModifyResponse",
        8: "AddRequest",
        9: "AddResponse",
        10: "DelRequest",
        11: "DelResponse",
        12: "ModDNRequest",
        13: "ModDNResponse",
        14: "ComparRequest",
        15: "ComparResponse",
        19: "SearchResultReference",
        24: "ExtendedRequest",
        25: "ExtendedResponse",
    }
    return names.get(msg_type, f"Message {value}" if value is not None else "traffic")


def ntp_mode_name(value: object) -> str:
    mode = parse_int(value)
    names = {
        1: "Symmetric Active",
        2: "Symmetric Passive",
        3: "Client",
        4: "Server",
        5: "Broadcast",
        6: "Broadcast Client",
        7: "Reserved",
    }
    return names.get(mode, f"Mode {value}" if value is not None else "traffic")


def bgp_message_name(value: object) -> str:
    msg_type = parse_int(value)
    names = {
        1: "OPEN",
        2: "UPDATE",
        3: "NOTIFICATION",
        4: "KEEPALIVE",
        5: "ROUTE-REFRESH",
    }
    return names.get(msg_type, f"Message {value}" if value is not None else "traffic")


def ospf_message_name(value: object) -> str:
    msg_type = parse_int(value)
    names = {
        1: "Hello",
        2: "Database Description",
        3: "Link State Request",
        4: "Link State Update",
        5: "Link State Acknowledgment",
    }
    return names.get(msg_type, f"Message {value}" if value is not None else "traffic")
