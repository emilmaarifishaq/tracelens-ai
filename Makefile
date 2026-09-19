.PHONY: help start stop restart health-check logs clean install

help:
	@echo ""
	@echo "TraceLens AI - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make install          Install all dependencies"
	@echo "  make setup            Setup Python venv and Node modules"
	@echo ""
	@echo "Running Services:"
	@echo "  make start            Start API and web (using script)"
	@echo "  make docker-start     Start with Docker Compose"
	@echo "  make docker-prod      Start production setup with Docker"
	@echo ""
	@echo "Management:"
	@echo "  make stop             Stop all services"
	@echo "  make restart          Restart all services"
	@echo "  make health-check     Run health checks"
	@echo "  make logs             Show service logs"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            Clean build artifacts"
	@echo "  make clean-all        Clean everything including venv"
	@echo "  make clean-docker     Remove Docker volumes"
	@echo ""
	@echo "URLs (when running):"
	@echo "  Web UI:   http://localhost:3000"
	@echo "  API:      http://localhost:8000"
	@echo "  Docs:     http://localhost:8000/docs"
	@echo ""

# Setup targets
install:
	@echo "Installing dependencies..."
	@which python3 > /dev/null || (echo "Python 3.12+ required" && exit 1)
	@which node > /dev/null || (echo "Node.js 20+ required" && exit 1)
	@which tshark > /dev/null || (echo "TShark required (install Wireshark)" && exit 1)
	@echo "✓ All dependencies installed"

setup: install
	@echo "Setting up project..."
	@cp .env.example .env 2>/dev/null || true
	@cd apps/api && python3 -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt || true
	@cd apps/web && npm install --silent || true
	@mkdir -p uploads decoded samples/external
	@echo "✓ Setup complete"

# Start targets
start: setup
	@echo "Starting services..."
	@chmod +x start.sh
	@./start.sh

docker-start:
	@echo "Starting with Docker Compose..."
	@docker compose up --build

docker-prod:
	@echo "Starting production setup..."
	@docker compose -f docker-compose.prod.yml up --build

# Management targets
stop:
	@echo "Stopping services..."
	@docker compose down 2>/dev/null || true
	@pkill -f "uvicorn" || true
	@pkill -f "npm run dev" || true
	@pkill -f "next dev" || true
	@echo "✓ Services stopped"

restart: stop start

health-check:
	@chmod +x health_check.sh
	@./health_check.sh

logs:
	@docker compose logs -f --tail=100

# Cleanup targets
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf apps/api/__pycache__
	@rm -rf apps/web/.next
	@rm -rf apps/web/dist
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete
	@echo "✓ Cleaned"

clean-all: clean
	@echo "Cleaning Python and Node modules..."
	@rm -rf apps/api/.venv
	@rm -rf apps/web/node_modules
	@rm -rf apps/web/package-lock.json
	@rm -rf .env
	@echo "✓ Deep clean complete"

clean-docker:
	@echo "Removing Docker volumes..."
	@docker compose down -v
	@docker compose -f docker-compose.prod.yml down -v
	@echo "✓ Docker cleaned"

# Aliases
dev: start
dev-docker: docker-start
prod: docker-prod
check: health-check
