# TraceLens AI

AI-powered trace analyzer for telecom and network protocol troubleshooting.

TraceLens AI turns uploaded PCAP/PCAPNG files into readable protocol flows, detects errors with transparent rules, and prepares evidence-based context for AI analysis.

## MVP Scope

- PCAP upload API
- Multiple PCAP upload and correlation
- TShark-based packet decoding
- Normalized event model
- GTPv2-C and Diameter starter extraction
- Rule-based error detection
- AI-ready trace summary payload
- AI explanation endpoint with offline fallback
- Endpoint mapping with manual YAML/JSON and Kubernetes pod YAML
- Next.js web interface for trace upload, ladder flow review, frame details, error summary, and AI analysis

## Target Protocols

Initial focus:

- GTPv1/GTPv2-C
- GTP-U
- Diameter
- SCTP
- DNS
- SIP/RTP basics

Expansion path:

- PFCP
- NGAP
- NAS EPS / NAS 5GS
- S1AP
- HTTP/2 SBI
- RADIUS
- Any future protocol with a decoder and normalizer

## Architecture

```text
PCAP Upload
  -> Decode Worker
  -> TShark JSON
  -> Protocol Normalizer
  -> Flow Correlator
  -> Rule Engine
  -> AI Context Builder
  -> UI Report + AI Assistant
```

## Local Development

Requirements:

- Docker
- TShark/Wireshark CLI for local decoder execution
- Node.js 20+
- Python 3.12+

Start the API and supporting services:

```bash
docker compose up --build
```

Run the web app separately during development:

```bash
cd apps/web
npm install
npm run dev
```

Run the API locally:

```bash
cd apps/api
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## AI Design

AI receives structured, redacted trace evidence instead of raw PCAP bytes. Every AI answer should cite frame numbers and state when evidence is insufficient.

The API exposes `POST /analysis/explain`. Without `OPENAI_API_KEY`, TraceLens returns the local rule-engine explanation so troubleshooting still works offline. When `OPENAI_API_KEY` is configured, the same endpoint sends the masked AI context to the OpenAI Responses API and includes the model answer beside the rule-engine baseline.

Optional environment:

```bash
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-5
```
