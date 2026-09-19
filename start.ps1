# TraceLens AI - Windows Startup Script
# Run with: powershell -ExecutionPolicy Bypass -File start.ps1

$ErrorActionPreference = "Stop"

# Colors
function Write-Success { Write-Host "✓ $args" -ForegroundColor Green }
function Write-Error-Custom { Write-Host "✗ $args" -ForegroundColor Red }
function Write-Info { Write-Host "→ $args" -ForegroundColor Cyan }
function Write-Warning-Custom { Write-Host "⚠ $args" -ForegroundColor Yellow }

Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     TraceLens AI - Startup Helper       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
Set-Location $scriptPath

# 1. Check dependencies
Write-Host "[1/6] Checking dependencies..." -ForegroundColor Yellow

$missingDeps = $false

@("node", "python", "tshark") | ForEach-Object {
    try {
        $version = & $_ --version 2>&1 | Select-Object -First 1
        Write-Success "$_ found: $version"
    } catch {
        Write-Error-Custom "$_ not found"
        $missingDeps = $true

        # Suggest installation
        Write-Info "Installation help:"
        switch ($_) {
            "node" {
                Write-Info "  Option 1 - Chocolatey: choco install nodejs"
                Write-Info "  Option 2 - Download: https://nodejs.org/download/"
            }
            "python" {
                Write-Info "  Option 1 - Chocolatey: choco install python"
                Write-Info "  Option 2 - Download: https://python.org/downloads"
            }
            "tshark" {
                Write-Info "  Download Wireshark: https://wireshark.org/download"
                Write-Info "  (Make sure TShark is selected during installation)"
                Write-Info "  Then add to PATH: C:\Program Files\Wireshark"
            }
        }
    }
}

if ($missingDeps) {
    Write-Host ""
    Write-Error-Custom "Missing dependencies detected"
    Write-Info "After installing dependencies above, run this script again"
    Write-Host ""
    exit 1
}

# 2. Setup .env file
Write-Host ""
Write-Host "[2/6] Setting up environment..." -ForegroundColor Yellow

if (!(Test-Path ".env")) {
    Write-Info "Creating .env file from .env.example..."
    Copy-Item ".env.example" ".env"
    Write-Success ".env created"
} else {
    Write-Success ".env already exists"
}

# 3. Setup Python virtual environment
Write-Host ""
Write-Host "[3/6] Setting up Python virtual environment..." -ForegroundColor Yellow

if (!(Test-Path "apps\api\.venv")) {
    Write-Info "Creating Python virtual environment..."
    Push-Location "apps\api"
    python -m venv .venv
    & ".\\.venv\\Scripts\\activate.ps1"
    python -m pip install -q --upgrade pip
    pip install -q -r requirements.txt
    Pop-Location
    Write-Success "Python environment ready"
} else {
    Write-Success "Python environment already exists"
}

# 4. Setup Node modules
Write-Host ""
Write-Host "[4/6] Installing Node dependencies..." -ForegroundColor Yellow

if (!(Test-Path "apps\web\node_modules")) {
    Write-Info "Installing npm packages..."
    Push-Location "apps\web"
    npm install --silent
    Pop-Location
    Write-Success "Node dependencies installed"
} else {
    Write-Success "Node dependencies already installed"
}

# 5. Create necessary directories
Write-Host ""
Write-Host "[5/6] Creating data directories..." -ForegroundColor Yellow

@("uploads", "decoded", "samples\external") | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force > $null
    }
}
Write-Success "Data directories ready"

# 6. Start services
Write-Host ""
Write-Host "[6/6] Starting services..." -ForegroundColor Yellow
Write-Host ""

Write-Info "Starting API backend (http://localhost:8000)..."
Push-Location "apps\api"
$env:PYTHONUNBUFFERED = "1"
& ".\\.venv\\Scripts\\activate.ps1"
Start-Process powershell -ArgumentList "-NoExit -Command", "cd '$scriptPath\apps\api'; .\.venv\Scripts\activate.ps1; uvicorn app.main:app --reload --host 127.0.0.1 --port 8000" -PassThru
Pop-Location

Start-Sleep -Seconds 3
Write-Success "API starting (check window for status)"

Write-Info "Starting web frontend (http://localhost:3000)..."
Push-Location "apps\web"
$env:NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000"
Start-Process powershell -ArgumentList "-NoExit -Command", "cd '$scriptPath\apps\web'; npm run dev" -PassThru
Pop-Location

Start-Sleep -Seconds 4
Write-Success "Web frontend starting (check window for status)"

# Print startup summary
Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║        All services started! 🎉        ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Green

Write-Host ""
Write-Host "📍 Access URLs:" -ForegroundColor Cyan
Write-Host "   Web UI:  http://localhost:3000" -ForegroundColor Green
Write-Host "   API:     http://localhost:8000" -ForegroundColor Green
Write-Host "   Docs:    http://localhost:8000/docs" -ForegroundColor Green

Write-Host ""
Write-Host "⏹️  To stop services, close the terminal windows" -ForegroundColor Cyan
Write-Host ""
Write-Host "Waiting for services to run..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
