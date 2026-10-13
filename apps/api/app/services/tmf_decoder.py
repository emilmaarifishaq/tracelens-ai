"""
TMF (Trace Measurement Format) decoder for Nokia/Ericsson traces.

Converts TMF binary format to TraceLens event format, enabling direct analysis
of vendor traces without PCAP conversion.

TMF Structure:
  - Magic: 0xf634f634 (4 bytes)
  - Header: Metadata (field headers, version, etc.)
  - Messages: Repeating "msg0" records containing protocol data
  - Each message: TLV-encoded protocol signaling (GTP, Diameter, HTTP/2, etc.)

Reference: 3GPP TS 32.423 (Trace file format and management)
"""

import struct
import json
from typing import Any, BinaryIO, Iterator
from datetime import datetime, timedelta


class TMFDecoder:
    """Decode Nokia/Ericsson TMF trace files."""

    MAGIC = b"\xf6\x34\xf6\x34"

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        self.file_size = 0
        self.header_info = {}

    def open(self) -> bool:
        """Open and validate TMF file."""
        try:
            self.file = open(self.filepath, "rb")
            self.file.seek(0, 2)
            self.file_size = self.file.tell()
            self.file.seek(0)

            # Validate magic
            magic = self.file.read(4)
            if magic != self.MAGIC:
                print(f"Warning: Unknown magic bytes: {magic.hex()}")

            return True
        except Exception as e:
            print(f"Error opening TMF file: {e}")
            return False

    def close(self):
        """Close TMF file."""
        if self.file:
            self.file.close()

    def parse_header(self) -> dict:
        """Parse TMF header metadata."""
        try:
            self.file.seek(0)
            self.file.read(4)  # Skip magic

            header_info = {
                "magic": self.MAGIC.hex(),
                "file_size": self.file_size,
                "format": "TMF",
            }

            # Try to extract header fields
            header_data = self.file.read(500)
            if b"nver" in header_data:
                idx = header_data.find(b"nver")
                version_bytes = header_data[idx + 8 : idx + 32]
                try:
                    version = version_bytes.split(b"\x00")[0].decode("utf-8", errors="ignore")
                    header_info["version"] = version
                except:
                    pass

            return header_info
        except Exception as e:
            print(f"Error parsing header: {e}")
            return {}

    def extract_messages(self) -> Iterator[dict]:
        """Extract all msg0 records from TMF file."""
        try:
            self.file.seek(0)
            self.file.read(4)  # Skip magic

            while True:
                pos = self.file.tell()
                if pos >= self.file_size - 8:
                    break

                # Look for msg0 marker
                chunk = self.file.read(4)
                if chunk != b"msg0":
                    self.file.seek(pos + 1)  # Search forward byte by byte
                    continue

                # Read message length
                len_bytes = self.file.read(4)
                if len(len_bytes) < 4:
                    break

                msg_len = struct.unpack(">I", len_bytes)[0]

                # Sanity check
                if msg_len > 100000 or msg_len < 10:
                    self.file.seek(pos + 1)
                    continue

                # Read message data
                msg_data = self.file.read(msg_len)
                if len(msg_data) < msg_len:
                    break

                yield {
                    "offset": pos,
                    "length": msg_len,
                    "data": msg_data,
                }

        except Exception as e:
            print(f"Error extracting messages: {e}")

    def decode_message(self, msg: dict) -> dict:
        """Decode a single TMF message into TraceLens event format."""
        try:
            data = msg["data"]
            event = {
                "frame": msg["offset"] // 1000,  # Use offset as frame reference
                "timestamp": datetime.now().isoformat(),
                "protocol": "UNKNOWN",
                "src": "tmf",
                "dst": "trace",
                "message": f"TMF Message ({len(data)} bytes)",
            }

            # Try to extract protocol indicators from message
            # Look for common protocol markers
            if b"DIA" in data:
                event["protocol"] = "Diameter"
                event["message"] = "Diameter signaling"
            elif b"GTP" in data or b"\x20" in data[:1]:
                event["protocol"] = "GTP"
                event["message"] = "GTP signaling"
            elif b"HTTP" in data or b"\x88" in data[:1]:
                event["protocol"] = "HTTP2-SBI"
                event["message"] = "HTTP/2 SBI (5G Service Based Interface)"
            elif b"NGAP" in data or b"\x00\x0c" in data:
                event["protocol"] = "NGAP"
                event["message"] = "NGAP (RAN signaling)"
            elif b"PFCP" in data or b"\x20" in data[:1]:
                event["protocol"] = "PFCP"
                event["message"] = "PFCP (SMF-UPF control)"

            # Extract any readable strings (FQDN, hostnames, etc.)
            strings = self._extract_strings(data)
            if strings:
                event["strings"] = strings

            return event

        except Exception as e:
            print(f"Error decoding message: {e}")
            return {}

    def _extract_strings(self, data: bytes, min_len: int = 4) -> list:
        """Extract human-readable strings from binary data."""
        strings = []
        current = b""

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    try:
                        s = current.decode("utf-8")
                        # Filter out garbage
                        if len(s) < 256 and s.isprintable():
                            strings.append(s)
                    except:
                        pass
                current = b""

        if len(current) >= min_len:
            try:
                s = current.decode("utf-8")
                if len(s) < 256 and s.isprintable():
                    strings.append(s)
            except:
                pass

        # Filter for relevant strings (FQDNs, network elements)
        relevant = [
            s
            for s in strings
            if any(
                x in s
                for x in [
                    ".3gppnetwork.org",
                    "amf",
                    "upf",
                    "udm",
                    "smf",
                    "ausf",
                    "nrf",
                    "pcf",
                    "mnc",
                    "mcc",
                    "@",
                ]
            )
        ]

        return relevant if relevant else strings[:5]

    def to_tracelen_format(self) -> dict:
        """Convert entire TMF trace to TraceLens format."""
        if not self.open():
            return {}

        try:
            header = self.parse_header()
            events = []

            for msg in self.extract_messages():
                event = self.decode_message(msg)
                if event:
                    events.append(event)

            result = {
                "trace_id": self.filepath.split("/")[-1],
                "filename": self.filepath,
                "format": "TMF",
                "events": events,
                "event_count": len(events),
                "errors": [],
                "ai_context": {
                    "trace_summary": {
                        "event_count": len(events),
                        "error_count": len(
                            [e for e in events if e.get("protocol") != "UNKNOWN"]
                        ),
                        "protocols": list(set(e.get("protocol", "UNKNOWN") for e in events)),
                    }
                },
            }

            return result

        finally:
            self.close()


def convert_tmf_to_tracelen(filepath: str) -> dict:
    """Convenience function to convert TMF file to TraceLens format."""
    decoder = TMFDecoder(filepath)
    return decoder.to_tracelen_format()
