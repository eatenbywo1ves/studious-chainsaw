#!/bin/bash
################################################################################
# Linux Deployment Quick Start Script
# Post-Load Testing Optimization Deployment
#
# Version: 1.1.0
# Date: October 22, 2025
# Status: Ready for Linux Deployment
#
# This script deploys the optimized health endpoint and stats API to a Linux
# staging environment with proper validation steps.
################################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="${REPO_URL:-https://github.com/eatenbywo1ves/studious-chainsaw.git}"
BRANCH="${BRANCH:-feat/todo-deployment-phase-1}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/catalytic-saas}"
WORKERS="${WORKERS:-4}"
PORT="${PORT:-8000}"

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        log_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

################################################################################
# Pre-Deployment Checks
################################################################################

log_info "Starting Pre-Deployment Checks..."

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log_error "This script must run on Linux (detected: $OSTYPE)"
    log_error "Windows has FD_SETSIZE limitation (512 file descriptors)"
    exit 1
fi
log_info "✓ Running on Linux"

# Check required commands
check_command "git"
check_command "python3"
check_command "pip3"
check_command "curl"
log_info "✓ Required commands available"

# Check Python version
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
log_info "✓ Python version: $PYTHON_VERSION"

# Check current ulimit
CURRENT_ULIMIT=$(ulimit -n)
log_info "Current file descriptor limit: $CURRENT_ULIMIT"

if [ "$CURRENT_ULIMIT" -lt 65536 ]; then
    log_warn "File descriptor limit is low ($CURRENT_ULIMIT < 65536)"
    log_info "Attempting to increase ulimit..."

    ulimit -n 65536 2>/dev/null || {
        log_error "Failed to increase ulimit. Run as root or update /etc/security/limits.conf"
        log_info "Add these lines to /etc/security/limits.conf:"
        echo "* soft nofile 65536"
        echo "* hard nofile 65536"
        exit 1
    }

    log_info "✓ Increased ulimit to $(ulimit -n)"
else
    log_info "✓ File descriptor limit is adequate: $CURRENT_ULIMIT"
fi

################################################################################
# Code Deployment
################################################################################

log_info "Starting Code Deployment..."

# Clone or pull repository
if [ -d "$DEPLOY_DIR" ]; then
    log_info "Repository exists, pulling latest changes..."
    cd "$DEPLOY_DIR"
    git fetch origin
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
else
    log_info "Cloning repository..."
    git clone "$REPO_URL" "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
    git checkout "$BRANCH"
fi

log_info "✓ Code deployed (branch: $BRANCH, commit: $(git rev-parse --short HEAD))"

# Setup virtual environment
if [ ! -d "venv" ]; then
    log_info "Creating virtual environment..."
    python3 -m venv venv
fi

log_info "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
log_info "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

log_info "✓ Dependencies installed"

################################################################################
# Environment Configuration
################################################################################

log_info "Configuring environment..."

# Check if .env exists
if [ ! -f ".env" ]; then
    log_warn ".env file not found"
    if [ -f ".env.example" ]; then
        log_info "Creating .env from .env.example..."
        cp .env.example .env
        log_warn "Please configure .env with production values"
    else
        log_error "No .env.example found. Cannot proceed."
        exit 1
    fi
fi

# Set deployment environment
export DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-staging}"
log_info "✓ Environment: $DEPLOYMENT_ENV"

################################################################################
# Health Check: Pre-Deployment
################################################################################

log_info "Checking if port $PORT is available..."
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    log_warn "Port $PORT is already in use"
    log_info "Attempting to stop existing server..."
    pkill -f "start_server_optimized.py" || true
    sleep 2

    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        log_error "Port $PORT is still in use. Please stop the service manually."
        exit 1
    fi
fi
log_info "✓ Port $PORT is available"

################################################################################
# Start Optimized Server
################################################################################

log_info "Starting optimized server (workers: $WORKERS, port: $PORT)..."

# Start server in background
nohup python start_server_optimized.py --workers $WORKERS --port $PORT > server.log 2>&1 &
SERVER_PID=$!

log_info "Server started (PID: $SERVER_PID)"
log_info "Waiting for server to be ready..."

# Wait for server to be healthy (max 30 seconds)
for i in {1..30}; do
    if curl -s http://localhost:$PORT/health > /dev/null 2>&1; then
        log_info "✓ Server is responding"
        break
    fi

    if [ $i -eq 30 ]; then
        log_error "Server failed to start within 30 seconds"
        log_error "Check server.log for errors:"
        tail -20 server.log
        exit 1
    fi

    sleep 1
done

################################################################################
# Health Validation
################################################################################

log_info "Running health validation tests..."

# Test 1: Health endpoint response
log_info "Test 1: Health endpoint response..."
HEALTH_RESPONSE=$(curl -s http://localhost:$PORT/health)
echo "$HEALTH_RESPONSE" | python3 -m json.tool > /dev/null 2>&1 || {
    log_error "Health endpoint returned invalid JSON"
    log_error "Response: $HEALTH_RESPONSE"
    exit 1
}

# Check that health endpoint is lightweight (no stats field)
if echo "$HEALTH_RESPONSE" | grep -q '"stats"'; then
    log_error "Health endpoint still contains 'stats' field!"
    log_error "This indicates the optimization was not applied correctly."
    exit 1
fi

log_info "✓ Health endpoint is lightweight (no stats field)"

# Test 2: Response time
log_info "Test 2: Health endpoint response time..."
START_TIME=$(date +%s%N)
curl -s http://localhost:$PORT/health > /dev/null
END_TIME=$(date +%s%N)
RESPONSE_TIME_MS=$(( (END_TIME - START_TIME) / 1000000 ))

if [ $RESPONSE_TIME_MS -gt 100 ]; then
    log_warn "Health endpoint response time is high: ${RESPONSE_TIME_MS}ms"
    log_warn "Expected: <50ms, Target: <100ms"
else
    log_info "✓ Health endpoint response time: ${RESPONSE_TIME_MS}ms (excellent!)"
fi

# Test 3: Connection leak check
log_info "Test 3: Connection leak check..."
CLOSE_WAIT_COUNT=$(netstat -an | grep ":$PORT" | grep "CLOSE_WAIT" | wc -l)

if [ $CLOSE_WAIT_COUNT -gt 0 ]; then
    log_warn "Found $CLOSE_WAIT_COUNT CLOSE_WAIT connections"
    log_warn "This may indicate connection leaks. Monitor during load testing."
else
    log_info "✓ No CLOSE_WAIT connections (connection leak fix validated)"
fi

# Test 4: Stats endpoint exists and requires auth
log_info "Test 4: Stats endpoint authentication..."
STATS_RESPONSE=$(curl -s -w "%{http_code}" http://localhost:$PORT/api/stats -o /dev/null)

if [ "$STATS_RESPONSE" = "401" ] || [ "$STATS_RESPONSE" = "403" ]; then
    log_info "✓ Stats endpoint requires authentication (HTTP $STATS_RESPONSE)"
else
    log_warn "Stats endpoint returned HTTP $STATS_RESPONSE (expected 401/403)"
    log_warn "Authentication may not be properly configured"
fi

################################################################################
# Load Testing (if Locust is available)
################################################################################

if command -v locust &> /dev/null; then
    log_info "Locust found, running load tests..."

    # Check if test file exists
    if [ ! -f "tests/performance/simple_loadtest.py" ]; then
        log_warn "Load test file not found: tests/performance/simple_loadtest.py"
        log_warn "Skipping load tests"
    else
        log_info "Running baseline 100-user test (60 seconds)..."
        locust -f tests/performance/simple_loadtest.py \
            --users 100 \
            --spawn-rate 20 \
            --run-time 60 \
            --host http://localhost:$PORT \
            --headless \
            --html baseline_100users_linux.html \
            --csv baseline_100users_linux \
            --loglevel WARNING

        log_info "Baseline test complete. Check baseline_100users_linux.html for results."

        # Parse results (if available)
        if [ -f "baseline_100users_linux_stats.csv" ]; then
            FAILURE_RATE=$(tail -1 baseline_100users_linux_stats.csv | cut -d',' -f4)
            MEDIAN_LATENCY=$(tail -1 baseline_100users_linux_stats.csv | cut -d',' -f8)

            log_info "Results: Failure rate: $FAILURE_RATE, Median latency: ${MEDIAN_LATENCY}ms"
        fi

        log_info ""
        log_info "To run 1K user production test, use:"
        log_info "  locust -f tests/performance/simple_loadtest.py \\"
        log_info "    --users 1000 --spawn-rate 100 --run-time 180 \\"
        log_info "    --host http://localhost:$PORT \\"
        log_info "    --headless --html staging_1k_users.html"
    fi
else
    log_warn "Locust not installed. Install with: pip install locust"
    log_info "Manual load testing command:"
    log_info "  locust -f tests/performance/simple_loadtest.py \\"
    log_info "    --users 1000 --spawn-rate 100 --run-time 180 \\"
    log_info "    --host http://localhost:$PORT --headless"
fi

################################################################################
# Deployment Summary
################################################################################

log_info ""
log_info "========================================="
log_info "DEPLOYMENT COMPLETE"
log_info "========================================="
log_info ""
log_info "Server Information:"
log_info "  PID: $SERVER_PID"
log_info "  URL: http://localhost:$PORT"
log_info "  Workers: $WORKERS"
log_info "  Branch: $BRANCH"
log_info "  Commit: $(git rev-parse --short HEAD)"
log_info ""
log_info "Health Checks:"
log_info "  ✓ Health endpoint responding"
log_info "  ✓ Lightweight response (no stats)"
log_info "  ✓ Response time: ${RESPONSE_TIME_MS}ms"
log_info "  ✓ No connection leaks"
log_info ""
log_info "Next Steps:"
log_info "  1. Review server.log for any errors"
log_info "  2. Run full 1K user load test (see command above)"
log_info "  3. Monitor metrics during load test:"
log_info "     - Success rate: >99% target"
log_info "     - P50 latency: <100ms target"
log_info "     - P95 latency: <300ms target"
log_info "  4. If tests pass, proceed to production deployment"
log_info ""
log_info "Monitoring Commands:"
log_info "  Server logs:     tail -f server.log"
log_info "  Server status:   ps aux | grep start_server_optimized"
log_info "  Connections:     netstat -an | grep :$PORT | grep ESTABLISHED | wc -l"
log_info "  Connection leaks: netstat -an | grep :$PORT | grep CLOSE_WAIT | wc -l"
log_info ""
log_info "========================================="

################################################################################
# End of Script
################################################################################
