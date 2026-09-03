# TraceLens AI Installation Guide

This guide explains how to install and run TraceLens AI on a laptop or PC.

TraceLens does not require Docker. Docker is optional. For day-to-day development on a Mac, the native install is usually easier.

## What You Will Run

TraceLens has two local services:

- API backend: receives PCAP files, runs TShark decode, applies local protocol rules, and returns the analysis.
- Web frontend: browser UI for upload, ladder flow, detected errors, and explanation.

Default URLs:

- Web UI: `http://localhost:3000`
- API: `http://localhost:8000`

## Prerequisites

Install these first:

- Git
- Python 3.12 or newer
- Node.js 20 or newer
- Wireshark/TShark CLI

TShark is important. Without TShark, TraceLens cannot decode most real PCAP files.

## Option 1: Mac Native Install

Install dependencies with Homebrew:

```bash
brew install git python@3.12 node wireshark
```

Check the tools:

```bash
git --version
python3 --version
node --version
npm --version
tshark --version
```

Clone the repo:

```bash
git clone https://github.com/emilmaarifishaq/tracelens-ai.git
cd tracelens-ai
```

Create the API virtual environment:

```bash
cd apps/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the API:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open a second terminal, then start the web UI:

```bash
cd tracelens-ai/apps/web
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

If the web UI uses a non-default API URL, create `apps/web/.env.local`:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## Option 2: Docker Backend Plus Local Web

Use this when you want PostgreSQL and Redis started automatically.

Install:

- Docker Desktop
- Node.js 20 or newer
- Git

Clone and start the backend stack:

```bash
git clone https://github.com/emilmaarifishaq/tracelens-ai.git
cd tracelens-ai
docker compose up --build
```

In another terminal, start the web UI:

```bash
cd tracelens-ai/apps/web
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

Stop Docker services:

```bash
docker compose down
```

## Option 3: Windows Native Install

Install:

- Git for Windows
- Python 3.12 or newer
- Node.js 20 or newer
- Wireshark with TShark selected during installation

Clone:

```powershell
git clone https://github.com/emilmaarifishaq/tracelens-ai.git
cd tracelens-ai
```

Create the API virtual environment:

```powershell
cd apps\api
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Start the API:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open a second PowerShell terminal:

```powershell
cd tracelens-ai\apps\web
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

If `tshark` is not found, add the Wireshark install folder to your Windows `PATH`. The default folder is usually:

```text
C:\Program Files\Wireshark
```

## Optional AI Setup

TraceLens works without an AI API key. In that mode, the explanation comes from the local TraceLens rule engine and knowledge files.

Optional AI provider config can be added later by creating a `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Then edit:

```bash
AI_PROVIDER=openai
AI_API_KEY=sk-...
AI_MODEL=gpt-5
AI_WEB_SEARCH_ENABLED=false
```

No raw PCAP bytes are sent to AI. TraceLens sends structured, masked trace evidence.

## Verify Installation

Run backend compile check:

```bash
cd apps/api
source .venv/bin/activate
python -m compileall app scripts
```

Run sample smoke tests from the repo root:

```bash
PYTHONPATH=apps/api apps/api/.venv/bin/python apps/api/scripts/smoke_test_samples.py
```

Expected output:

```text
PASS GTPv2-C failure sample
PASS CPE DNS failure sample
PASS local failure rule coverage
PASS sample smoke tests
```

Run web production build:

```bash
cd apps/web
npm run build
```

## How To Use

1. Open `http://localhost:3000`.
2. Upload a `.pcap` or `.pcapng` file.
3. Review `Failure Focus` first.
4. Review the ladder view to see source, destination, frame, and protocol flow.
5. Select an event to inspect frame details.
6. Click `Explain Locally` for deterministic local explanation.
7. Use `Copy ChatGPT Prompt` only when you want additional external AI review without an API key.

## Troubleshooting

### TShark Not Found

Check:

```bash
tshark --version
```

If it fails on Mac:

```bash
brew install wireshark
```

If it fails on Windows, add `C:\Program Files\Wireshark` to `PATH`.

### Web Opens But Upload Fails

Make sure the API is running:

```text
http://localhost:8000/health
```

If the frontend is not using the correct backend URL, create `apps/web/.env.local`:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

Restart `npm run dev`.

### Port Already In Use

For API, use another port:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

Then set:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8001
```

For web:

```bash
npm run dev -- --port 3011
```

Open:

```text
http://localhost:3011
```

### Python Virtual Environment Not Active

Mac/Linux prompt should use:

```bash
source apps/api/.venv/bin/activate
```

Windows PowerShell should use:

```powershell
apps\api\.venv\Scripts\activate
```

### Browser Shows Old Version

Stop the web server, then remove Next cache:

```bash
cd apps/web
rm -rf .next
npm run dev
```

On Windows PowerShell:

```powershell
cd apps\web
Remove-Item -Recurse -Force .next
npm run dev
```
