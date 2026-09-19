#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    TraceLens AI - Health Check         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

FAILED=0
PASSED=0

check() {
    local name=$1
    local url=$2
    local expected=$3

    echo -n "Checking $name... "

    if response=$(curl -s "$url" 2>/dev/null); then
        if [[ $response == *"$expected"* ]]; then
            echo -e "${GREEN}✓ OK${NC}"
            ((PASSED++))
        else
            echo -e "${RED}✗ FAILED${NC} (unexpected response)"
            echo "  Expected: $expected"
            echo "  Got: $response"
            ((FAILED++))
        fi
    else
        echo -e "${RED}✗ FAILED${NC} (connection refused)"
        ((FAILED++))
    fi
}

# Check API
echo -e "${YELLOW}API Checks:${NC}"
check "API Health" "http://localhost:8000/health" "status"
check "API Docs" "http://localhost:8000/docs" "swagger"

# Check Web
echo ""
echo -e "${YELLOW}Web UI Checks:${NC}"
check "Web Frontend" "http://localhost:3000" "html"

# Check dependencies
echo ""
echo -e "${YELLOW}Dependencies:${NC}"

echo -n "Checking Python... "
if command -v python3 &> /dev/null; then
    version=$(python3 --version 2>&1)
    echo -e "${GREEN}✓${NC} $version"
    ((PASSED++))
else
    echo -e "${RED}✗ Not found${NC}"
    ((FAILED++))
fi

echo -n "Checking Node.js... "
if command -v node &> /dev/null; then
    version=$(node --version 2>&1)
    echo -e "${GREEN}✓${NC} $version"
    ((PASSED++))
else
    echo -e "${RED}✗ Not found${NC}"
    ((FAILED++))
fi

echo -n "Checking TShark... "
if command -v tshark &> /dev/null; then
    version=$(tshark --version 2>&1 | head -n1)
    echo -e "${GREEN}✓${NC} $version"
    ((PASSED++))
else
    echo -e "${RED}✗ Not found${NC}"
    ((FAILED++))
fi

# Check environment
echo ""
echo -e "${YELLOW}Environment:${NC}"

echo -n "Checking .env file... "
if [ -f .env ]; then
    echo -e "${GREEN}✓ Found${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ Missing${NC} (run ./start.sh to create)"
    ((FAILED++))
fi

echo -n "Checking uploads directory... "
if [ -d uploads ]; then
    echo -e "${GREEN}✓ Exists${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ Missing${NC} (will be created automatically)"
fi

echo -n "Checking decoded directory... "
if [ -d decoded ]; then
    echo -e "${GREEN}✓ Exists${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ Missing${NC} (will be created automatically)"
fi

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}║     ✓ All checks passed! 🎉            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}║     ✗ $FAILED check(s) failed           ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    exit 1
fi
