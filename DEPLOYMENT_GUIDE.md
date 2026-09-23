# TraceLens AI - Deployment Guide

Complete guide for deploying TraceLens AI to production with detailed prerequisites, configuration, and multi-provider AI setup.

---

## 📋 Prerequisites - REQUIRED

Before deploying TraceLens AI, you **must** have these installed:

### System Requirements

#### Operating System
- ✅ Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, RHEL 8+)
- ✅ macOS 12+ (Intel or Apple Silicon)
- ✅ Windows 10/11 (WSL2 recommended for Linux subsystem)

#### Core Dependencies

| Requirement | Minimum | Recommended | Why Needed |
|-----------|---------|------------|-----------|
| **Python** | 3.12.0 | 3.12+ | Backend API, PCAP decoding |
| **Node.js** | 20.0 | 22+ | Web frontend React/Next.js |
| **TShark/Wireshark** | 4.0+ | Latest stable | Protocol packet decoding |
| **Git** | Any version | Latest | Clone and version control |

#### Network/Storage Assumptions
- **Disk space**: Minimum 2GB free (for app + sample uploads)
- **Memory**: Minimum 2GB RAM
- **Network**: Outbound HTTPS (443) if using cloud AI providers
- **Ports**: 3000 (web), 8000 (API) -- no database or cache service required

---

## 🔧 Installation by Platform

### macOS (Homebrew)

```bash
# Install all dependencies at once
brew install python@3.12 node wireshark git

# Verify installations
python3 --version      # Should be 3.12+
node --version         # Should be 20+
npm --version          # Comes with Node.js
tshark --version       # Should be 4.0+
```

### Linux - Ubuntu/Debian

```bash
# Update package manager
sudo apt-get update

# Install dependencies
sudo apt-get install -y \
  python3.12 python3.12-venv python3-pip \
  nodejs npm \
  wireshark wireshark-common \
  git

# Verify installations
python3 --version      # Should be 3.12+
node --version         # Should be 20+
tshark --version       # Should be 4.0+
```

### Linux - CentOS/RHEL

```bash
# Install dependencies
sudo yum install -y \
  python312 python312-devel \
  nodejs \
  wireshark \
  git

# Verify installations
python3.12 --version
node --version
tshark --version
```

### Windows (Recommended: Use WSL2)

**Option A: WSL2 + Ubuntu (Easiest)**
1. Install WSL2: `wsl --install`
2. Open Ubuntu terminal in WSL2
3. Follow Linux - Ubuntu/Debian instructions above

**Option B: Native Windows PowerShell**

#### Method 1: Using Chocolatey (Easiest)

If you have Chocolatey installed, run in PowerShell (as Administrator):

```powershell
choco install python nodejs wireshark -y

# Verify installation
python --version
node --version
tshark --version
```

#### Method 2: Manual Download (Step-by-Step)

**Step 1: Install Python 3.12 or 3.13**
1. Download: https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe
   - **⚠️ DO NOT use Python 3.14** - Dependencies don't support it yet
   - Use Python 3.12 LTS or 3.13 only
2. Run the installer
3. ⚠️ **IMPORTANT**: Check "Add Python 3.12 to PATH" during installation
4. Click "Install Now"
5. Wait for completion
6. Verify in new PowerShell window:
   ```powershell
   python --version
   ```
   Should show `3.12.x` or `3.13.x` (NOT 3.14)

**Step 2: Install Node.js**
1. Download: https://nodejs.org/dist/v22.9.0/node-v22.9.0-x64.msi
2. Run the installer
3. Click "Next" through the wizard
4. Accept license agreement
5. Keep default installation path
6. Click "Install"
7. Verify in new PowerShell window:
   ```powershell
   node --version
   npm --version
   ```

**Step 3: Install Wireshark (includes TShark)**
1. Download: https://www.wireshark.org/download/win64/Wireshark-latest-x64-installer.exe
2. Run the installer
3. Click "Next" to proceed
4. **⚠️ IMPORTANT**: On "Choose Components" screen, ensure **TShark** is checked (✓)
5. Keep default installation path: `C:\Program Files\Wireshark`
6. Complete installation
7. Add to PATH (PowerShell as Administrator):
   ```powershell
   [Environment]::SetEnvironmentVariable(
     "Path",
     "$env:Path;C:\Program Files\Wireshark",
     "User"
   )
   ```
8. **Close and reopen PowerShell** for PATH changes to take effect
9. Verify in new PowerShell window:
   ```powershell
   tshark --version
   ```

#### Verify All Installations

Open **new PowerShell window** and run:

```powershell
python --version      # Should show 3.12.x
node --version        # Should show v20+ or v22+
npm --version         # Should show npm version
tshark --version      # Should show TShark version
```

If any command shows "not found", the PATH wasn't updated. Close all PowerShell windows, reopen as Administrator, and verify again.

### Docker (Alternative - No Dependencies Needed)

If you have Docker, you don't need to install Python, Node, or TShark:

```bash
# Install Docker Desktop
# macOS: https://docker.com/products/docker-desktop
# Windows: https://docker.com/products/docker-desktop
# Linux: https://docs.docker.com/engine/install/

# Verify
docker --version
docker compose --version
```

---

## 🚀 Deployment Methods

### Method 1: Automated Script (Recommended for Development)

**Best for:** Local development, testing, quick demos

```bash
# Clone repository
git clone https://github.com/emilmaarifishaq/tracelens-ai.git
cd tracelens-ai

# Make script executable
chmod +x start.sh

# Run startup script
./start.sh

# Script will:
# ✓ Check all dependencies
# ✓ Create .env automatically
# ✓ Set up Python virtual environment
# ✓ Install Node dependencies
# ✓ Start API and web frontend
# ✓ Print URLs
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
```

**URLs after startup:**
- Web UI: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Method 2: Docker Compose (Development)

**Best for:** Full stack (API + web) with no local Python/Node/TShark dependencies

```bash
# Clone repository
git clone https://github.com/emilmaarifishaq/tracelens-ai.git
cd tracelens-ai

# First time
docker compose up --build

# After that
docker compose up

# Stop
docker compose down
```

**URLs:**
- Web UI: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Method 3: Docker Compose Production

**Best for:** Cloud deployment, production-grade setup

```bash
# Use production docker-compose file
docker compose -f docker-compose.prod.yml up --build -d

# View logs
docker compose -f docker-compose.prod.yml logs -f

# Stop
docker compose -f docker-compose.prod.yml down
```

**Includes:**
- Health checks on both services (web waits for the API to report healthy)
- Persistent volume for uploaded/decoded trace files
- Environment-based AI provider configuration

### Method 4: Manual Setup (Full Control)

**Best for:** Custom infrastructure, Kubernetes, advanced deployments

```bash
# Clone
git clone https://github.com/emilmaarifishaq/tracelens-ai.git
cd tracelens-ai

# Setup API
cd apps/api
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Start API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# In another terminal, setup Web
cd apps/web
npm install
npm run build
npm start
```

---

## 🔑 AI Provider Configuration

TraceLens works **offline by default** using local rule engine. Optional AI providers can be added via environment variables.

### Environment Variables Setup

Create `.env` file in project root:

```bash
# Copy template
cp .env.example .env

# Edit with your provider settings
nano .env  # or use your editor
```

### Configuration Options

#### 1. Rule Engine (Offline - Default)
```bash
AI_PROVIDER=rule-engine
# No API key needed
# No base URL needed
# Always works, perfect for development
```

#### 2. OpenAI (Chat GPT)
```bash
AI_PROVIDER=openai
AI_API_KEY=sk-...  # From https://platform.openai.com/api-keys
AI_MODEL=gpt-4o    # Options: gpt-4o, gpt-4-turbo, gpt-4, gpt-3.5-turbo
AI_BASE_URL=https://api.openai.com/v1/chat/completions
AI_WEB_SEARCH_ENABLED=true  # Optional: enable web search
```

**Get API Key:**
1. Go to https://platform.openai.com/api-keys
2. Click "Create new secret key"
3. Copy the key (starts with `sk-`)
4. Paste into `.env`

#### 3. Claude (Anthropic)
```bash
AI_PROVIDER=claude
AI_API_KEY=sk-ant-...  # From https://console.anthropic.com/
AI_MODEL=claude-3-5-sonnet-20241022
# Options: claude-3-5-sonnet-20241022, claude-3-opus-20240229, claude-3-sonnet-20240229
AI_BASE_URL=https://api.anthropic.com/v1/messages
```

**Get API Key:**
1. Go to https://console.anthropic.com/
2. Click "Create Key" in API Keys section
3. Copy the key (starts with `sk-ant-`)
4. Paste into `.env`

#### 4. Azure OpenAI (Enterprise)
```bash
AI_PROVIDER=azure
AI_API_KEY=your-azure-key
AI_MODEL=your-deployment-name
AI_BASE_URL=https://your-resource.openai.azure.com/v1/chat/completions
```

**Get Setup Details:**
1. Log into Azure Portal
2. Find your OpenAI resource
3. Go to Keys section
4. Copy Key 1 and endpoint
5. Configure above

#### 5. Ollama (Local LLM - Free)
```bash
AI_PROVIDER=ollama
# AI_API_KEY not needed for local Ollama
AI_MODEL=llama2  # Options: llama2, mistral, neural-chat, openhermes
AI_BASE_URL=http://localhost:11434/api/chat
```

**Setup Ollama:**
1. Install from https://ollama.ai
2. Pull a model: `ollama pull llama2`
3. Start: `ollama serve`
4. Verify: http://localhost:11434/api/tags
5. Configure above in TraceLens

#### 6. Generic Endpoint (Groq, Mistral, etc.)
```bash
AI_PROVIDER=generic
AI_API_KEY=your-api-key
AI_MODEL=your-model-name
AI_BASE_URL=https://api.your-provider.com/v1/chat/completions
```

**Examples:**

**Groq (Fast, Free):**
```bash
AI_PROVIDER=generic
AI_API_KEY=gsk_...  # From https://console.groq.com/keys
AI_MODEL=mixtral-8x7b-32768
AI_BASE_URL=https://api.groq.com/openai/v1/chat/completions
```

**Mistral:**
```bash
AI_PROVIDER=generic
AI_API_KEY=sk_...  # From https://console.mistral.ai/
AI_MODEL=mistral-small
AI_BASE_URL=https://api.mistral.ai/v1/chat/completions
```

---

## ✅ Verify Installation

After deployment, verify everything works:

```bash
# Check API is running
curl http://localhost:8000/health
# Expected: {"status":"ok"}

# Check web frontend loads
curl http://localhost:3000
# Expected: HTML response

# Check API documentation
# Open: http://localhost:8000/docs
```

### Upload Test File

1. Open http://localhost:3000
2. Click "Upload PCAP"
3. Select a test file (samples available in `samples/` folder)
4. Click "Analyze"
5. Should see results within seconds

---

## 🔒 Security Considerations

### For Production Deployment:

1. **API Keys:**
   - ✓ Never commit `.env` to version control
   - ✓ Use `.env` only locally or via secret management
   - ✓ For Docker, use Docker secrets or environment variables
   - ✓ For cloud, use managed secret services (AWS Secrets Manager, Azure Key Vault, etc.)

2. **HTTPS:**
   - ✓ Use reverse proxy (nginx, Traefik) for HTTPS
   - ✓ Terminate TLS at edge
   - ✓ Use self-signed certs for internal only

3. **Network:**
   - ✓ Restrict API to internal networks only
   - ✓ Use firewall rules to limit access
   - ✓ Consider VPN/bastion host for remote access

4. **Data:**
   - ✓ PCAP files contain network traffic - sensitive!
   - ✓ Implement access controls
   - ✓ Consider encryption at rest
   - ✓ Set up log retention policies

---

## 🐛 Troubleshooting

### TShark Not Found

```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install wireshark

# Windows
# Add C:\Program Files\Wireshark to PATH
# Restart terminal
```

### Port Already In Use

```bash
# Find process using port
lsof -i :8000       # macOS/Linux
netstat -ano | findstr :8000  # Windows

# Kill process or use different port
# For API, edit start.sh or use uvicorn --port 8001
```

### Python Version Not Supported (pydantic-core error)

**Error:** `the configured Python interpreter version (3.14) is newer than PyO3's maximum supported version (3.13)`

**Cause:** You installed Python 3.14, but dependencies only support up to Python 3.13

**Solution:**

**Option 1: Use Python 3.13 (Recommended)**
1. Uninstall Python 3.14
2. Download and install Python 3.13: https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe
3. Make sure to check "Add Python 3.13 to PATH"
4. Delete the `.venv` folder: `rm -rf apps/api/.venv`
5. Create new virtual environment and reinstall:
   ```bash
   cd apps/api
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

**Option 2: Use Python 3.12 (Most Stable)**
1. Uninstall Python 3.14
2. Download and install Python 3.12: https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe
3. Follow the same steps as Option 1

### Python Virtual Environment Issues

```bash
# Remove and recreate
rm -rf apps/api/.venv
python3 -m venv apps/api/.venv
source apps/api/.venv/bin/activate
pip install -r apps/api/requirements.txt
```

### Frontend Can't Reach API

```bash
# Create .env.local in apps/web/
echo "NEXT_PUBLIC_API_BASE_URL=http://localhost:8000" > apps/web/.env.local

# Restart web server
npm run dev
```

### Docker Issues

```bash
# Clear everything
docker compose down -v

# Rebuild
docker compose up --build

# Check logs
docker compose logs -f
```

---

## 📊 Performance Tuning

### For Large PCAP Files (>500MB):

```bash
# Python: Increase memory
export PYTHONUNBUFFERED=1

# Node: Increase heap
NODE_OPTIONS="--max-old-space-size=4096" npm start

# API workers (uvicorn)
uvicorn app.main:app --workers 4 --port 8000
```

---

## 📚 Next Steps

After successful deployment:

1. **Upload test PCAP** - Generate one with `python3 samples/make_gtpc_failure_sample.py /tmp/sample.pcap` (no real capture is committed to the repo)
2. **Test protocols** - Try different protocol types
3. **Configure AI** - Add OpenAI, Claude, or other provider
4. **Review flows** - Explore ladder view and error detection
5. **Customize rules** - Modify `apps/api/app/knowledge/` for your protocols

---

## 🆘 Getting Help

- **Issues:** https://github.com/emilmaarifishaq/tracelens-ai/issues
- **Docs:** See README.md, QUICK_START.md, installation.md
- **API Docs:** http://localhost:8000/docs (interactive Swagger)

---

## ✨ Summary

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| Script | Automated, simple | Requires all deps | Development |
| Docker | No deps needed | Uses more resources | Testing, CI/CD |
| Production Docker | Production-grade, scaling | More complex | Cloud, production |
| Manual | Full control | Complex setup | Custom infra |

**Recommendation for Production:**
- Use `docker-compose.prod.yml`
- Set up reverse proxy (nginx/Traefik) for HTTPS
- Use managed secrets for API keys
- Enable health checks and monitoring
