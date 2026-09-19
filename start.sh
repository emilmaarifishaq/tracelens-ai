#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     TraceLens AI - Startup Helper       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}→${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 1. Check dependencies
echo -e "\n${YELLOW}[1/6]${NC} Checking dependencies..."

check_command() {
    if command -v "$1" &> /dev/null; then
        local version=$("$1" "$2" 2>&1 | head -n1)
        print_status "$1 found: $version"
        return 0
    else
        print_error "$1 not found"
        return 1
    fi
}

MISSING_DEPS=0

if ! check_command "node" "--version"; then
    print_warning "Node.js not found. Install from https://nodejs.org/"
    MISSING_DEPS=1
fi

if ! check_command "python3" "--version"; then
    print_warning "Python 3 not found. Install from https://python.org/"
    MISSING_DEPS=1
fi

if ! check_command "tshark" "--version"; then
    print_warning "TShark not found. Install Wireshark from https://wireshark.org/"
    MISSING_DEPS=1
fi

if [ $MISSING_DEPS -eq 1 ]; then
    print_error "Please install missing dependencies and try again"
    exit 1
fi

# 2. Setup .env file
echo -e "\n${YELLOW}[2/6]${NC} Setting up environment..."

if [ ! -f .env ]; then
    print_info "Creating .env file from .env.example..."
    cp .env.example .env
    print_status ".env created"
else
    print_status ".env already exists"
fi

# Set default values if not already set
if ! grep -q "UPLOAD_DIR" .env; then
    echo "UPLOAD_DIR=uploads" >> .env
fi

if ! grep -q "DECODED_DIR" .env; then
    echo "DECODED_DIR=decoded" >> .env
fi

# 3. Setup Python virtual environment
echo -e "\n${YELLOW}[3/6]${NC} Setting up Python virtual environment..."

if [ ! -d "apps/api/.venv" ]; then
    print_info "Creating Python virtual environment..."
    cd apps/api
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    cd "$SCRIPT_DIR"
    print_status "Python environment ready"
else
    print_status "Python environment already exists"
fi

# 4. Setup Node modules
echo -e "\n${YELLOW}[4/6]${NC} Installing Node dependencies..."

if [ ! -d "apps/web/node_modules" ]; then
    print_info "Installing npm packages..."
    cd apps/web
    npm install --silent
    cd "$SCRIPT_DIR"
    print_status "Node dependencies installed"
else
    print_status "Node dependencies already installed"
fi

# 5. Create necessary directories
echo -e "\n${YELLOW}[5/6]${NC} Creating data directories..."

mkdir -p uploads decoded samples/external
print_status "Data directories ready"

# 6. Start services
echo -e "\n${YELLOW}[6/6]${NC} Starting services...\n"

print_info "Starting API backend (http://localhost:8000)..."
cd apps/api
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 &
API_PID=$!
cd "$SCRIPT_DIR"

# Wait for API to start
sleep 3

# Check if API is running
if ! kill -0 $API_PID 2>/dev/null; then
    print_error "Failed to start API server"
    exit 1
fi

print_status "API running (PID: $API_PID)"

print_info "Starting web frontend (http://localhost:3000)..."
cd apps/web
export NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
npm run dev &
WEB_PID=$!
cd "$SCRIPT_DIR"

sleep 4
print_status "Web frontend running (PID: $WEB_PID)"

# Print startup summary
echo -e "\n${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        All services started! 🎉        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}📍 Access URLs:${NC}"
echo -e "   Web UI:  ${GREEN}http://localhost:3000${NC}"
echo -e "   API:     ${GREEN}http://localhost:8000${NC}"
echo -e "   Docs:    ${GREEN}http://localhost:8000/docs${NC}"

echo -e "\n${BLUE}📌 Process IDs:${NC}"
echo -e "   API:  $API_PID"
echo -e "   Web:  $WEB_PID"

echo -e "\n${BLUE}⏹️  To stop services:${NC}"
echo -e "   ${YELLOW}kill $API_PID $WEB_PID${NC}"
echo -e "   Or press ${YELLOW}Ctrl+C${NC}"

# Cleanup on exit
trap "kill $API_PID $WEB_PID 2>/dev/null; echo -e '\n${YELLOW}Services stopped${NC}'" EXIT

# Keep script running
wait
