#!/usr/bin/env bash
#
# SaaS Platform Load Testing Runner
# Bash script to execute comprehensive load tests
#
# Usage:
#   ./run_load_tests.sh [baseline|1k|10k|both] [host] [duration_minutes]
#
# Examples:
#   ./run_load_tests.sh baseline              # 100 users baseline test
#   ./run_load_tests.sh 1k                    # 1K users test
#   ./run_load_tests.sh 10k                   # 10K users test
#   ./run_load_tests.sh both                  # Run all tests
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

TEST_TYPE="${1:-both}"
HOST="${2:-http://localhost:8000}"
DURATION="${3:-5}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${CYAN}================================================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

print_header "SaaS Platform Load Testing - Pre-Flight Checks"

# Check if Locust is installed
print_info "Checking Locust installation..."
if python -m locust --version &> /dev/null; then
    LOCUST_VERSION=$(python -m locust --version 2>&1 | head -1)
    print_success "Locust is installed: $LOCUST_VERSION"
else
    print_error "Locust is not installed!"
    print_info "Install with: pip install locust"
    exit 1
fi

# Check if API server is running
print_info "Checking if SaaS API server is running on $HOST..."
if curl -s "$HOST/health" > /dev/null 2>&1; then
    print_success "API server is running and healthy"
else
    print_error "API server is not accessible at $HOST"
    print_info "Start the server first:"
    print_info "  cd saas"
    print_info "  python -m uvicorn api.saas_server:app --host 0.0.0.0 --port 8000"
    print_warning "Continuing anyway - tests will fail if server isn't running..."
fi

# Change to tests/performance directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/tests/performance"

if [[ -d "$TEST_DIR" ]]; then
    cd "$TEST_DIR"
    print_success "Changed to test directory: $TEST_DIR"
else
    print_error "Test directory not found: $TEST_DIR"
    exit 1
fi

# Check if locustfile exists
if [[ ! -f "locustfile.py" ]]; then
    print_error "locustfile.py not found in current directory!"
    exit 1
fi

# ============================================================================
# RUN TESTS
# ============================================================================

run_load_test() {
    local TEST_NAME="$1"
    local USERS="$2"
    local SPAWN_RATE="$3"
    local RUN_TIME="$4"
    local HOST_URL="$5"

    print_header "Running $TEST_NAME"
    print_info "Users: $USERS | Spawn Rate: $SPAWN_RATE/sec | Duration: $RUN_TIME min | Host: $HOST_URL"

    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local REPORT_NAME="loadtest_${TEST_NAME}_${TIMESTAMP}"

    # Run Locust in headless mode
    print_info "Starting Locust..."
    print_info "Command: locust -f locustfile.py --users $USERS --spawn-rate $SPAWN_RATE --run-time ${RUN_TIME}m --host $HOST_URL --html ${REPORT_NAME}.html --csv ${REPORT_NAME}"

    python -m locust \
        -f locustfile.py \
        --users "$USERS" \
        --spawn-rate "$SPAWN_RATE" \
        --run-time "${RUN_TIME}m" \
        --host "$HOST_URL" \
        --headless \
        --html "${REPORT_NAME}.html" \
        --csv "${REPORT_NAME}" \
        --loglevel INFO

    if [[ $? -eq 0 ]]; then
        print_success "$TEST_NAME completed successfully!"
        print_info "HTML Report: ${TEST_DIR}/${REPORT_NAME}.html"
        print_info "CSV Data: ${TEST_DIR}/${REPORT_NAME}_stats.csv"
    else
        print_error "$TEST_NAME failed with exit code $?"
    fi

    # Brief pause between tests
    if [[ "$TEST_TYPE" == "both" ]]; then
        print_info "Waiting 30 seconds before next test..."
        sleep 30
    fi
}

# ============================================================================
# EXECUTE TESTS BASED ON TYPE
# ============================================================================

case "$TEST_TYPE" in
    baseline)
        print_header "Running Baseline Test (100 users)"
        run_load_test "baseline_100users" 100 20 2 "$HOST"
        ;;

    1k)
        print_header "Running 1K Users Test"
        run_load_test "1k_users" 1000 100 "$DURATION" "$HOST"
        ;;

    10k)
        print_header "Running 10K Users Test"
        run_load_test "10k_users" 10000 200 "$DURATION" "$HOST"
        ;;

    both)
        print_header "Running Complete Load Test Suite"

        # Baseline test
        run_load_test "baseline_100users" 100 20 2 "$HOST"

        # 1K users test
        run_load_test "1k_users" 1000 100 "$DURATION" "$HOST"

        # 10K users test
        run_load_test "10k_users" 10000 200 "$DURATION" "$HOST"
        ;;

    *)
        print_error "Invalid test type: $TEST_TYPE"
        print_info "Valid options: baseline, 1k, 10k, both"
        exit 1
        ;;
esac

# ============================================================================
# SUMMARY
# ============================================================================

print_header "Load Testing Complete!"

print_info "Test reports saved in: $TEST_DIR"
print_info ""
print_info "Next steps:"
print_info "  1. Review HTML reports for detailed metrics"
print_info "  2. Check that P95 response time < 200ms"
print_info "  3. Verify success rate > 99%"
print_info "  4. Look for connection pool exhaustion errors"
print_info "  5. If all pass → proceed to staging deployment!"
print_info ""

# List all generated reports
print_info "Generated reports:"
ls -lh loadtest_*.html 2>/dev/null || print_warning "No HTML reports found"

print_success "Load testing session complete!"
