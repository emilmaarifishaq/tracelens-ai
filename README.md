# TraceLens AI

AI-powered trace analyzer for telecom and network protocol troubleshooting.

TraceLens AI turns uploaded PCAP/PCAPNG files into readable protocol flows, detects errors with transparent rules, and prepares evidence-based context for AI analysis.

## MVP Scope

- PCAP upload API
- Multiple PCAP upload and correlation
- TShark-based packet decoding
- Normalized event model
- Host and URL extraction from DNS, HTTP, TLS SNI, SIP URI, MQTT topic, and QUIC SNI when present. TLS/QUIC HTTPS URLs are inferred as `https://host` unless decrypted HTTP evidence is available.
- GTPv2-C and Diameter starter extraction
- Rule-based error detection
- Local protocol knowledge library for error codes, likely root cause, recommended checks, and procedure grouping
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
- DHCP
- DNS
- TCP/UDP basics
- HTTP/TLS
- SIP/IMS starter failure detection
- MQTT/QUIC/SSH traffic labeling
- PFCP starter cause-code detection
- RTP basics

Expansion path:

- PFCP
- NGAP
- NAS EPS / NAS 5GS
- S1AP
- HTTP/2 SBI
- RADIUS
- Any future protocol with a decoder and normalizer

CPE and internet-access traces are supported at a starter level with readable DHCP, DNS, TCP, TLS, HTTP, MQTT, QUIC, SSH, ICMP, and ARP event labels plus basic DHCP/DNS/TCP/TLS/HTTP issue detection.

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

For full setup instructions, see [Installation Guide](docs/installation.md).

Requirements:

- Docker, optional
- TShark/Wireshark CLI for local decoder execution
- Node.js 20+
- Python 3.12+

Optional Docker backend stack:

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

TraceLens is local-knowledge first and AI second. The decoder, normalizer, error-code library, and procedure rules produce the baseline troubleshooting result before any AI provider is used.

Local knowledge lives in:

- `apps/api/app/knowledge/error_codes.yaml`
- `apps/api/app/knowledge/procedure_rules.yaml`

AI receives structured, redacted trace evidence instead of raw PCAP bytes. Every AI answer should cite frame numbers and state when evidence is insufficient.

The API exposes `POST /analysis/explain`. Without an AI provider key, TraceLens returns the local rule-engine explanation so troubleshooting still works offline. When an AI provider is configured, the same endpoint sends the masked AI context to the provider and includes the model answer beside the rule-engine baseline.

TraceLens is designed as a provider gateway, not an OpenAI-only tool. The first supported hosted provider is OpenAI Responses. The same boundary can support OpenAI-compatible endpoints later, including private enterprise gateways or local model servers.

Optional web search is a separate switch. When `AI_WEB_SEARCH_ENABLED=true` with the OpenAI provider, TraceLens can let the model use hosted web search for public references such as standards notes, vendor documentation, or known error-code context. Raw PCAP bytes are still not sent; the model receives only the structured, masked trace evidence.

If no API key is available, the in-app explanation comes from the local TraceLens rule engine. Use the ChatGPT Web handoff when you want external AI with a normal ChatGPT web account: after decoding a trace, click `Copy ChatGPT Prompt`, open https://chatgpt.com/, and paste the generated masked prompt. This keeps TraceLens usable without an API subscription while avoiding brittle browser automation.

Optional environment:

```bash
AI_PROVIDER=openai
AI_API_KEY=sk-...
AI_MODEL=gpt-5
AI_BASE_URL=https://api.openai.com/v1/responses
AI_WEB_SEARCH_ENABLED=true
```

## Sample Capture Testing

TraceLens uses generated telecom samples for controlled failure tests and will use selected public captures for protocol regression coverage. See [docs/sample-capture-strategy.md](docs/sample-capture-strategy.md).

Curated 4G/5G sample metadata lives in [samples/external-captures.yaml](samples/external-captures.yaml). Download approved external captures locally with:

```bash
apps/api/.venv/bin/python samples/download_external_captures.py --technology 5G
apps/api/.venv/bin/python samples/download_external_captures.py --technology 4G
```

Downloaded captures are stored under `samples/external/` and are intentionally ignored by Git.

Run deterministic smoke tests against local samples:

```bash
PYTHONPATH=apps/api apps/api/.venv/bin/python apps/api/scripts/smoke_test_samples.py
```
