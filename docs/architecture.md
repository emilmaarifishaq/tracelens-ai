# Architecture

TraceLens AI separates packet decoding from analysis.

## Components

- Web app: upload, timeline, packet details, flow view, AI assistant
- API: trace metadata, upload orchestration, analysis endpoints
- Decoder worker: runs TShark and protocol-specific normalizers
- Protocol package: dictionaries, error rules, flow templates
- AI layer: summarizes evidence and answers trace-specific questions

## Processing Pipeline

1. Receive PCAP/PCAPNG upload.
2. Store original file in controlled storage.
3. Decode using TShark JSON output.
4. Normalize protocol fields into trace events.
5. Correlate request/response pairs and sessions.
6. Apply transparent troubleshooting rules.
7. Build a redacted AI context bundle.
8. Render timeline, errors, and engineer-ready report.

## Accuracy Rule

AI analysis must be evidence-led. Conclusions should include frame numbers, protocol messages, result/cause codes, and uncertainty where applicable.

