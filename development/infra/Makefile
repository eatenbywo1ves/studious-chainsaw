# Catalytic Computing System - Makefile
# Common development and deployment tasks

.PHONY: help install install-dev clean test lint format type-check security-check \
        run-api run-webhook docker-build docker-run docker-compose-up \
        docker-compose-down migrate benchmark docs serve-docs pre-commit \
        setup-hooks check-all

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python
PIP := pip
DOCKER := docker
DOCKER_COMPOSE := docker-compose
PROJECT_NAME := catalytic-computing
API_PORT := 8080
WEBHOOK_PORT := 8085
METRICS_PORT := 9090

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

## help: Display this help message
help:
	@echo "$(BLUE)Catalytic Computing System - Development Tasks$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@echo ""
	@grep -E '^##' $(MAKEFILE_LIST) | sed -e 's/## //'

## === Installation ===

## install: Install production dependencies
install:
	@echo "$(YELLOW)Installing production dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)✓ Production dependencies installed$(NC)"

## install-dev: Install development dependencies
install-dev: install
	@echo "$(YELLOW)Installing development dependencies...$(NC)"
	$(PIP) install -r requirements-dev.txt
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

## install-gpu: Install GPU dependencies (CUDA required)
install-gpu:
	@echo "$(YELLOW)Installing GPU dependencies...$(NC)"
	$(PIP) install cupy-cuda11x torch
	@echo "$(GREEN)✓ GPU dependencies installed$(NC)"

## setup: Complete development environment setup
setup: install-dev setup-hooks
	@echo "$(YELLOW)Setting up development environment...$(NC)"
	cp -n .env.example .env || true
	mkdir -p logs cache uploads tmp data
	@echo "$(GREEN)✓ Development environment ready$(NC)"

## === Code Quality ===

## lint: Run code linting
lint:
	@echo "$(YELLOW)Running linters...$(NC)"
	flake8 . --count --statistics
	pylint *.py
	@echo "$(GREEN)✓ Linting complete$(NC)"

## format: Format code with black and isort
format:
	@echo "$(YELLOW)Formatting code...$(NC)"
	isort .
	black .
	@echo "$(GREEN)✓ Code formatted$(NC)"

## type-check: Run type checking with mypy
type-check:
	@echo "$(YELLOW)Running type checking...$(NC)"
	mypy . --install-types --non-interactive
	@echo "$(GREEN)✓ Type checking complete$(NC)"

## security-check: Run security checks with bandit
security-check:
	@echo "$(YELLOW)Running security checks...$(NC)"
	bandit -r . -f json -o security-report.json
	bandit -r . -f screen
	@echo "$(GREEN)✓ Security check complete$(NC)"

## check-all: Run all code quality checks
check-all: lint type-check security-check
	@echo "$(GREEN)✓ All checks passed$(NC)"

## === Testing ===

## test: Run all tests
test:
	@echo "$(YELLOW)Running tests...$(NC)"
	pytest -v --cov=. --cov-report=term-missing --cov-report=html

## test-unit: Run unit tests only
test-unit:
	@echo "$(YELLOW)Running unit tests...$(NC)"
	pytest -v -m unit

## test-integration: Run integration tests only
test-integration:
	@echo "$(YELLOW)Running integration tests...$(NC)"
	pytest -v -m integration

## test-gpu: Run GPU tests (requires CUDA)
test-gpu:
	@echo "$(YELLOW)Running GPU tests...$(NC)"
	$(PYTHON) test_gpu_cupy.py
	$(PYTHON) test_cuda_basic.py
	@echo "$(GREEN)✓ GPU tests complete$(NC)"

## benchmark: Run performance benchmarks
benchmark:
	@echo "$(YELLOW)Running benchmarks...$(NC)"
	$(PYTHON) memory_optimization_analyzer.py
	$(PYTHON) test_lattice_integration_suite.py
	@echo "$(GREEN)✓ Benchmarks complete$(NC)"

## === Development Servers ===

## run-api: Run the API server in development mode
run-api:
	@echo "$(YELLOW)Starting API server on port $(API_PORT)...$(NC)"
	uvicorn production_api_server:app --reload --host 0.0.0.0 --port $(API_PORT)

## run-webhook: Run the webhook server
run-webhook:
	@echo "$(YELLOW)Starting webhook server on port $(WEBHOOK_PORT)...$(NC)"
	$(PYTHON) webhook_server.py

## run-all: Run all services in parallel (requires GNU parallel)
run-all:
	@echo "$(YELLOW)Starting all services...$(NC)"
	parallel --jobs 3 ::: \
		"uvicorn production_api_server:app --host 0.0.0.0 --port $(API_PORT)" \
		"python webhook_server.py" \
		"prometheus --config.file=prometheus-config.yml"

## === Docker ===

## docker-build: Build Docker images
docker-build:
	@echo "$(YELLOW)Building Docker images...$(NC)"
	$(DOCKER) build -f Dockerfile.catalytic -t $(PROJECT_NAME):latest .
	$(DOCKER) build -f Dockerfile.webhook -t webhook-system:latest .
	@echo "$(GREEN)✓ Docker images built$(NC)"

## docker-run: Run API server in Docker
docker-run:
	@echo "$(YELLOW)Running API server in Docker...$(NC)"
	$(DOCKER) run -d --name $(PROJECT_NAME) \
		-p $(API_PORT):$(API_PORT) \
		-p $(METRICS_PORT):$(METRICS_PORT) \
		-v $(PWD)/logs:/app/logs \
		$(PROJECT_NAME):latest

## docker-compose-up: Start all services with Docker Compose
docker-compose-up:
	@echo "$(YELLOW)Starting services with Docker Compose...$(NC)"
	$(DOCKER_COMPOSE) -f docker-compose.webhook.yml up -d
	@echo "$(GREEN)✓ Services started$(NC)"

## docker-compose-down: Stop all Docker Compose services
docker-compose-down:
	@echo "$(YELLOW)Stopping Docker Compose services...$(NC)"
	$(DOCKER_COMPOSE) -f docker-compose.webhook.yml down
	@echo "$(GREEN)✓ Services stopped$(NC)"

## docker-logs: Show Docker logs
docker-logs:
	$(DOCKER_COMPOSE) -f docker-compose.webhook.yml logs -f

## === Database ===

## db-init: Initialize databases
db-init:
	@echo "$(YELLOW)Initializing databases...$(NC)"
	$(PYTHON) -c "from webhook_system import WebhookManager; WebhookManager('webhooks.db')"
	@echo "$(GREEN)✓ Databases initialized$(NC)"

## db-migrate: Run database migrations
db-migrate:
	@echo "$(YELLOW)Running database migrations...$(NC)"
	# Add migration commands here when implemented
	@echo "$(GREEN)✓ Migrations complete$(NC)"

## === Documentation ===

## docs: Build documentation
docs:
	@echo "$(YELLOW)Building documentation...$(NC)"
	cd docs && sphinx-build -b html source build
	@echo "$(GREEN)✓ Documentation built$(NC)"

## serve-docs: Serve documentation locally
serve-docs:
	@echo "$(YELLOW)Serving documentation on http://localhost:8000...$(NC)"
	cd docs/build && python -m http.server 8000

## === Git Hooks ===

## setup-hooks: Setup pre-commit hooks
setup-hooks:
	@echo "$(YELLOW)Setting up pre-commit hooks...$(NC)"
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"

## pre-commit: Run pre-commit on all files
pre-commit:
	@echo "$(YELLOW)Running pre-commit checks...$(NC)"
	pre-commit run --all-files

## === Deployment ===

## deploy-local: Deploy to local Kubernetes
deploy-local:
	@echo "$(YELLOW)Deploying to local Kubernetes...$(NC)"
	./deploy-local-production.sh

## deploy-prod: Deploy to production
deploy-prod:
	@echo "$(YELLOW)Deploying to production...$(NC)"
	./deploy-production.sh

## === Monitoring ===

## metrics: Show current metrics
metrics:
	@echo "$(YELLOW)Fetching metrics...$(NC)"
	curl -s http://localhost:$(METRICS_PORT)/metrics | grep -E "^(catalytic|webhook|lattice)"

## health-check: Check service health
health-check:
	@echo "$(YELLOW)Checking service health...$(NC)"
	@curl -s http://localhost:$(API_PORT)/health | jq . || echo "API server not responding"
	@curl -s http://localhost:$(WEBHOOK_PORT)/health | jq . || echo "Webhook server not responding"

## === Cleanup ===

## clean: Clean build artifacts and cache
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	rm -rf build/ dist/ htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf *.log security-report.json
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

## clean-docker: Clean Docker resources
clean-docker:
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	$(DOCKER) container prune -f
	$(DOCKER) image prune -f
	$(DOCKER) volume prune -f
	@echo "$(GREEN)✓ Docker cleanup complete$(NC)"

## clean-all: Clean everything including dependencies
clean-all: clean clean-docker
	@echo "$(YELLOW)Deep cleaning...$(NC)"
	rm -rf venv/ .venv/ node_modules/
	rm -rf logs/ cache/ uploads/ tmp/ data/
	@echo "$(GREEN)✓ Deep clean complete$(NC)"

## === Utilities ===

## version: Show version information
version:
	@echo "$(BLUE)Catalytic Computing System$(NC)"
	@echo "Version: 1.0.0"
	@echo "Python: $(shell python --version)"
	@echo "Docker: $(shell docker --version 2>/dev/null || echo 'Not installed')"

## env-check: Verify environment setup
env-check:
	@echo "$(YELLOW)Checking environment...$(NC)"
	@which python > /dev/null && echo "$(GREEN)✓ Python found$(NC)" || echo "$(RED)✗ Python not found$(NC)"
	@which docker > /dev/null && echo "$(GREEN)✓ Docker found$(NC)" || echo "$(RED)✗ Docker not found$(NC)"
	@which node > /dev/null && echo "$(GREEN)✓ Node.js found$(NC)" || echo "$(RED)✗ Node.js not found$(NC)"
	@test -f .env && echo "$(GREEN)✓ .env file exists$(NC)" || echo "$(YELLOW)⚠ .env file missing (run 'make setup')$(NC)"
	@python -c "import cupy" 2>/dev/null && echo "$(GREEN)✓ GPU support available$(NC)" || echo "$(YELLOW)⚠ GPU support not available$(NC)"

## logs: Tail application logs
logs:
	@echo "$(YELLOW)Tailing application logs...$(NC)"
	tail -f logs/*.log 2>/dev/null || echo "No log files found"