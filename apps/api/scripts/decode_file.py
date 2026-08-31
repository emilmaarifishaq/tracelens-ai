from pathlib import Path
import sys

from app.services.analysis import analyze_events
from app.services.decoder import decode_pcap


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python scripts/decode_file.py <trace.pcap>")
        return 2

    decoded = decode_pcap(Path(sys.argv[1]))
    analysis = analyze_events(decoded.events)

    print(f"trace_id={decoded.trace_id}")
    print(f"events={len(decoded.events)}")
    print(f"errors={len(analysis.errors)}")

    for event in decoded.events[:20]:
        inner = event.get("inner") or {}
        print(
            "frame={frame} protocol={protocol} message={message} teid={teid} src={src}:{src_port} dst={dst}:{dst_port} inner={inner_src}->{inner_dst}/{inner_proto}".format(
                frame=event.get("frame"),
                protocol=event.get("protocol"),
                message=event.get("message"),
                teid=event.get("teid"),
                src=event.get("src"),
                src_port=event.get("src_port"),
                dst=event.get("dst"),
                dst_port=event.get("dst_port"),
                inner_src=inner.get("src", "-"),
                inner_dst=inner.get("dst", "-"),
                inner_proto=inner.get("protocol", "-"),
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
