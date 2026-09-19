# TraceLens AI - Comprehensive Protocol Support

TraceLens AI now supports **40+ protocols** across multiple layers and use cases, far beyond traditional telecom-only packet analysis tools.

## 📊 Protocol Categories

### Telecom Signaling Protocols (4G/5G)
Advanced support for carrier-grade network diagnostics:

| Protocol | Ports | Support Level | Use Case |
|----------|-------|---------------|----------|
| **GTPv2-C** | 2123 | ✅ Full | LTE session management, bearer setup |
| **GTPv1-C** | 2123 | ✅ Full | 3G session management, legacy networks |
| **GTP-U** | 2152 | ⚠️ Partial | User plane data tunneling |
| **Diameter** | 3868, 3869 | ✅ Full | HSS/UDM authentication, subscriber queries |
| **S1AP** | 36412 | ⚠️ Partial | RAN signaling (LTE) |
| **NGAP** | 38412 | ⚠️ Partial | RAN signaling (5G) |
| **PFCP** | 8805 | ✅ Full | SMF-to-UPF control (5G) |
| **RADIUS** | 1812, 1813 | ⚠️ Partial | Legacy AAA authentication |

**Example: Analyze LTE Session Failures**
- See Create Session → cause code → root cause recommendation
- Filter by GTPv2-C to isolate control plane failures
- View Diameter AAA interactions with HSS

### Application Layer Protocols
Web, VoIP, IoT, and enterprise services:

| Protocol | Ports | Support Level | Use Case |
|----------|-------|---------------|----------|
| **HTTP/HTTPS** | 80, 443, 8080+ | ✅ Full | Web traffic, API calls, status codes |
| **HTTP/2** | 443, 8443 | ✅ Full | Modern multiplexed web |
| **DNS** | 53 | ✅ Full | Name resolution, NXDOMAIN failures |
| **SIP** | 5060, 5061 | ✅ Full | VoIP call signaling (IMS) |
| **RTP** | Dynamic | ⚠️ Partial | Voice/video media streams |
| **MQTT** | 1883, 8883 | ✅ Full | IoT pub/sub messaging |
| **QUIC** | 443, 80 | ✅ Full | Google's experimental protocol |
| **SMTP/POP3/IMAP** | 25, 110, 143+ | ⚠️ Partial | Email protocols |

**Example: Troubleshoot Web Traffic Issues**
- Identify 5xx errors and when they started
- See DNS NXDOMAIN errors preceding HTTP failures
- Track redirects (3xx) vs connection failures

### Transport & Network Protocols
The foundation of all communication:

| Protocol | Ports | Support Level | Use Case |
|----------|-------|---------------|----------|
| **TCP** | Multiple | ✅ Full | Connection reliability, flags (SYN/ACK/RST), retransmissions |
| **UDP** | Multiple | ✅ Full | Connectionless messaging |
| **SCTP** | 132, 36412, 38412 | ⚠️ Partial | Stream control (S1AP/NGAP transport) |
| **IPv4** | — | ✅ Full | Routing, TTL analysis |
| **IPv6** | — | ✅ Full | Next-gen routing |
| **ICMP** | — | ✅ Full | Echo (ping), Unreachable, Time Exceeded |
| **ICMPv6** | — | ✅ Full | IPv6 diagnostics |
| **ARP** | — | ✅ Full | IP-to-MAC resolution failures |

**Example: Network Connectivity Issues**
- TCP RST (reset) detection → sudden connection loss
- TCP retransmissions → packet loss, latency
- ICMP Unreachable → routing issues
- ARP failures → Layer 2 problems

### Security & Encryption Protocols
Secure and encrypted communications:

| Protocol | Ports | Support Level | Use Case |
|----------|-------|---------------|----------|
| **TLS/SSL** | 443, 3868+ | ✅ Full | Handshake details, SNI, cipher suites, alerts |
| **DTLS** | — | ⚠️ Partial | UDP encryption (QUIC, SRTP) |
| **SSH** | 22 | ⚠️ Partial | Remote terminal access |
| **IPSec** | 500, 4500 | ⚠️ Partial | VPN and site-to-site tunneling |

**Example: TLS Certificate Issues**
- Certificate alert (subject mismatch, expired)
- Handshake failures → version mismatch
- SNI mismatch between client and server

### Network Management & Enterprise Protocols
Operations, monitoring, and control:

| Protocol | Ports | Support Level | Use Case |
|----------|-------|---------------|----------|
| **SNMP** | 161, 162 | ⚠️ Partial | Device monitoring and alarms |
| **LDAP** | 389, 636 | ⚠️ Partial | Directory and authentication queries |
| **NTP** | 123 | ⚠️ Partial | Time synchronization |
| **BGP** | 179 | ⚠️ Partial | Inter-AS routing updates |
| **OSPF** | — | ⚠️ Partial | Intra-AS routing |

### Configuration & Infrastructure Protocols
Host setup and network provisioning:

| Protocol | Ports | Support Level | Use Case |
|----------|-------|---------------|----------|
| **DHCP** | 67, 68 | ✅ Full | IP address assignment (Discover/Offer/Request/ACK) |

---

## 🔍 Using the Protocol Filter

### Interactive Dropdown
1. **Click "Protocols" button** in the Flow Ladder panel
2. **Select/deselect** individual protocols
3. **View statistics** for each protocol:
   - Packet count
   - Error count
   - Ports used
   - Frame range
4. **Bulk actions:**
   - "Select All" → see everything
   - "Clear All" → reset filter
5. **Auto-categories:** Protocols grouped by type (Telecom, Application, Transport, etc.)

### Filtering Modes
- **No filter** (empty set): Show all events
- **Single protocol**: Isolate one protocol's traffic
- **Multiple protocols**: Compare cross-protocol flows (e.g., GTPv2-C + DNS + Diameter)
- **Combined with "Errors Only"**: Show only failures in selected protocols
- **Combined with search**: Find text patterns within filtered protocols

### Example Workflows

**1. Diagnose LTE Session Failure**
```
Protocols: Select GTPv2-C
View: Ladder shows Create Session → cause code
Action: Click error frame → AI explains cause
```

**2. Track Complete Call Flow (VoIP)**
```
Protocols: Select SIP, RTP, Diameter, DNS
View: See signaling (SIP) → auth (Diameter) → media (RTP)
Result: Identify where in flow call setup failed
```

**3. Web Application Troubleshooting**
```
Protocols: Select HTTP, HTTPS, DNS, TCP
View: See DNS → HTTP redirects → TLS handshakes
Find: Which redirect caused the error?
```

**4. 5G Bearer Setup**
```
Protocols: Select NGAP, PFCP, GTPv2-C, Diameter
View: RAN signaling → core signaling → auth → bearer setup
Analyze: Which component failed?
```

---

## 📈 Protocol Statistics

When a trace is uploaded, TraceLens calculates:

```json
{
  "protocol_statistics": {
    "GTPv2-C": {
      "count": 145,
      "first_frame": 12,
      "last_frame": 892,
      "error_count": 3,
      "ports": ["2123"]
    },
    "DNS": {
      "count": 8,
      "first_frame": 5,
      "last_frame": 850,
      "error_count": 1,
      "ports": ["53"]
    },
    "HTTP": {
      "count": 23,
      "first_frame": 67,
      "last_frame": 923,
      "error_count": 2,
      "ports": ["80", "8080"]
    }
  }
}
```

**Interpretation:**
- **count**: Total packets for this protocol
- **first_frame**: When protocol first appeared
- **last_frame**: When protocol last appeared
- **error_count**: Frames with protocol failures
- **ports**: Unique ports used (helps identify tunneling/port-shifting)

---

## 🎯 Use Cases by Protocol

### Telecom Operators (4G/5G)
✅ GTPv2-C, Diameter, S1AP, NGAP, PFCP
- Full LTE/5G stack analysis
- Subscriber authentication troubleshooting
- Bearer setup failure diagnosis
- Roaming partner connectivity

### Web/Cloud Services
✅ HTTP/HTTPS, DNS, TLS, TCP
- API performance analysis
- Certificate/TLS errors
- DNS resolution failures
- Redirect loop detection

### VoIP/IMS Services
✅ SIP, RTP, Diameter, DNS
- Call signaling failures
- Carrier authentication issues
- Media stream problems
- Call flow visualization

### IoT Platforms
✅ MQTT, QUIC, DNS, TLS
- Lightweight protocol analysis
- Pub/sub message flow
- Device connectivity issues

### Enterprise Networks
✅ SNMP, LDAP, BGP, OSPF, DNS
- Network monitoring
- Active directory issues
- Routing path analysis
- Management plane health

---

## 🚀 Expanding Protocol Support

### Currently Supported Decoders (TShark-based)
All protocols that TShark can decode:
- Latest TShark version: 100+ protocols
- Common: HTTP, DNS, SIP, TLS, QUIC, GTP, Diameter, etc.
- Legacy: POP, IMAP, SMTP, SNMP, LDAP, etc.

### Adding Custom Protocols
1. **Protocol already in TShark?** → Automatically decoded
2. **Need custom dissector?** → Submit PR with:
   - Normalization function (e.g., `normalize_custom_protocol`)
   - Message type mappings
   - Error code interpretations
   - Example test PCAP

### Decoder Architecture
```
TShark (JSON output) 
  → normalize_packet() 
    → [normalize_gtpv2, normalize_http, ...]
      → event dict with protocol-specific fields
        → Filter, search, analyze
```

---

## 📋 Protocol Mapping Reference

### Frame Layer (Raw Bytes)
- Ethernet MAC addresses
- VLAN tags
- Packet size/timing

### Network Layer (IP)
- IPv4/IPv6 addresses
- TTL/Hop Limit
- ICMP echo/unreachable

### Transport Layer (Ports)
- TCP/UDP/SCTP ports
- TCP flags (SYN, ACK, RST, FIN)
- TCP retransmissions

### Application Layer (Payloads)
- GTPv2-C: TEID, message type, cause code
- HTTP: Method, status, URL, host
- DNS: Query name, record type, response code
- SIP: Method, status code, call ID
- Diameter: Application ID, result code
- TLS: SNI, handshake type, alert

---

## ⚙️ Configuration

### HTTP/2 Port Override
By default, ports 29502-29509 are treated as HTTP/2 (for 5G SBI).
Customize in upload form or API:
```bash
curl -X POST http://localhost:8000/traces \
  -F "file=@trace.pcap" \
  -F "http2_ports=443,8443,29502,29503"
```

### Show/Hide Settings
- **Show Heartbeats**: Include keep-alive messages
- **Hide Duplicate PFCP**: Reduce noise from repeated rules

---

## 📚 Further Reading

- **3GPP 4G/5G Specs**: 
  - TS 29.274 (GTPv2-C)
  - TS 38.413 (NGAP)
  - TS 29.244 (PFCP)

- **IETF RFCs**:
  - RFC 7230 (HTTP/1.1)
  - RFC 7540 (HTTP/2)
  - RFC 3261 (SIP)
  - RFC 6733 (Diameter)

- **Protocol Standards**:
  - MQTT: [mqtt.org](https://mqtt.org)
  - QUIC: [quicprotocol.org](https://quicprotocol.org)

---

## 🤔 FAQ

**Q: My protocol isn't showing up. How do I add it?**
A: Check if TShark supports it: `tshark -G protocols | grep name`. If it exists, add a normalization function to `decoder.py`. If not, you need a TShark dissector plugin.

**Q: Can I filter by port number?**
A: Not directly, but search ":" to find port notation, or use protocol filter then search within that.

**Q: What if I have mixed 4G and 5G?**
A: Select both GTPv2-C and NGAP in filter. The timeline view shows which nodes used which protocol.

**Q: Why is some protocol data grayed out?**
A: Encrypted payloads (TLS, SSH) show handshake details but not application data. For TLS/HTTPS, see SNI and certificate info instead.

---

## 🔗 Related

- [QUICK_START.md](./QUICK_START.md) - Getting started
- [README.md](./README.md) - Project overview
- [AI Analysis](./apps/api/app/services/ai_analysis.py) - How AI explains protocols
- [Error Codes](./apps/api/app/knowledge/error_codes.yaml) - Cause code mappings
