# TraceLens AI - Quick Start Guide

Choose your preferred setup method below. **All options require one command to start.**

---

## ⚡ Option 1: Automated Script (Recommended for Development)

### Mac / Linux

```bash
chmod +x start.sh
./start.sh
```

This will:
- ✅ Detect and validate all dependencies (Python, Node, TShark)
- ✅ Create `.env` automatically
- ✅ Set up Python virtual environment
- ✅ Install Node dependencies
- ✅ Start both API and web frontend
- ✅ Print URLs and health status

**URLs:**
- Web UI: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
```

Same features as above, but opens services in separate terminal windows.

---

## 🐳 Option 2: Docker Compose (Easiest, No Dependencies)

Everything runs in containers. Just need Docker installed.

### First time only:

```bash
docker compose up --build
```

### After reboot:

```bash
docker compose up
```

To stop:
```bash
docker compose down
```

**URLs:**
- Web UI: http://localhost:3000
- API: http://localhost:8000

TraceLens has no database -- everything happens in-memory per request, with uploaded/decoded files under a shared `trace_data` volume so they survive a container restart.

---

## 🏢 Option 3: Production Docker (With All Services)

For cloud deployment or production-like setup:

```bash
docker compose -f docker-compose.prod.yml up --build
```

Features:
- Health checks on both services (web waits for the API to report healthy before starting)
- Environment variable configuration for the AI provider

---

## 🔧 First Time Setup

### Prerequisites Check

Before using any option, make sure you have:

**For Options 1:**
- [ ] Python 3.12+ (`python3 --version`)
- [ ] Node.js 20+ (`node --version`)
- [ ] TShark/Wireshark (`tshark --version`)

**For Option 2 & 3:**
- [ ] Docker Desktop installed
- [ ] Docker running

### Install Missing Dependencies

**Mac (Homebrew):**
```bash
brew install python@3.12 node wireshark
```

**Windows:**
- Python: https://python.org/downloads
- Node.js: https://nodejs.org
- Wireshark: https://wireshark.org/download

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install python3.12 python3.12-venv nodejs npm wireshark
```

---

## 📝 Configuration

### API Configuration

Create a `.env` file at the repo root (or it's auto-created by `start.sh`/`start.ps1`), copied from `.env.example`. It's read automatically on startup regardless of which directory you launch `uvicorn` from:

```bash
# File storage
UPLOAD_DIR=uploads
DECODED_DIR=decoded

# AI Provider (optional, server-side default -- the web UI's Settings panel
# can also set the provider/key per-request instead, without touching this file)
AI_PROVIDER=rule-engine
AI_API_KEY=sk-your-key-here
AI_MODEL=gpt-5
AI_WEB_SEARCH_ENABLED=false
```

### Web Configuration

For custom API URL, create `apps/web/.env.local`:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

---

## ✅ Verify Everything Works

### Option 1 & 2 (Script / Docker Compose)

After startup, test:

```bash
# Check API
curl http://localhost:8000/health

# Check Web
curl http://localhost:3000
```

Should return `{"status":"ok"}` and HTML respectively.

### Upload a Test File

The `samples/` folder doesn't ship a ready-made `.pcap` (real captures aren't committed to the repo), but it does include a generator for a small, deterministic failure trace:

```bash
python3 samples/make_gtpc_failure_sample.py /tmp/sample.pcap
```

Then:

1. Open http://localhost:3000
2. Click "Choose PCAP / PCAPNG" and select `/tmp/sample.pcap`
3. Click "Analyze"

You should see "Frames decoded: 5" and 2 detected GTPv2-C failures (cause 73, No Resources Available) within a couple of seconds.

---

## 🐛 Troubleshooting

### Issue: "Port already in use"

**Option 1 (Script):**
Edit `start.sh` and change:
```bash
--port 8001  # Change API port
```

Then in `apps/web/.env.local`:
```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8001
```

**Option 2 (Docker):**
```bash
docker compose down
```

### Issue: "TShark not found"

**Mac:**
```bash
brew install wireshark
```

**Windows:**
Add to PATH: `C:\Program Files\Wireshark`

**Linux:**
```bash
sudo apt-get install wireshark
```

### Issue: "Frontend can't reach API"

1. Check API is running: http://localhost:8000/health
2. If not, restart API service
3. Set correct API URL in `apps/web/.env.local`

### Issue: "API crashes on startup"

Check `.env` file exists and has required variables. Script auto-creates this.

### Issue: "Permission denied" on start.sh

```bash
chmod +x start.sh
./start.sh
```

### Issue: Docker service won't start

```bash
# Check if port is in use
docker ps

# Remove old containers
docker compose down -v

# Try again
docker compose up --build
```

---

## 🚀 Next Steps After Starting

1. **Upload a PCAP file** - Use sample from `samples/` folder
2. **Review Failures** - Check "Failure Focus" tab first
3. **Analyze Flows** - View ladder diagrams and frame details
4. **Get Explanations** - Click "Explain Locally" for instant analysis
5. **Add AI** (Optional) - Set `AI_API_KEY` in `.env` for ChatGPT explanations

---

## 📚 More Information

- **Full Setup:** See [docs/installation.md](docs/installation.md)
- **Architecture:** See [README.md](README.md#architecture)
- **API Docs:** Open http://localhost:8000/docs (interactive Swagger)
- **Sample Captures:** See [docs/sample-capture-strategy.md](docs/sample-capture-strategy.md)

---

## 🆘 Still Having Issues?

1. Check that all prerequisites are installed
2. Look at error messages carefully
3. Try Docker option if script doesn't work
4. Check `.env` file has all required variables
5. Make sure ports 3000, 8000 are available

Happy troubleshooting! 🎉
