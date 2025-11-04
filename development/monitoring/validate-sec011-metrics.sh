#!/bin/bash
# SEC-011 Metrics Validation Script
#
# Validates that SEC-011 request size limit metrics are properly
# instrumented, collected, and available in Prometheus.
#
# Usage: bash validate-sec011-metrics.sh [APP_URL] [PROMETHEUS_URL]
#
# Defaults:
#   APP_URL=http://localhost:8000
#   PROMETHEUS_URL=http://localhost:9090

set -e

# Configuration
APP_URL="${1:-http://localhost:8000}"
PROMETHEUS_URL="${2:-http://localhost:9090}"
METRICS_ENDPOINT="$APP_URL/metrics"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

echo "=================================================="
echo "SEC-011 Metrics Validation"
echo "=================================================="
echo "App URL:        $APP_URL"
echo "Prometheus URL: $PROMETHEUS_URL"
echo "Metrics URL:    $METRICS_ENDPOINT"
echo ""

# Helper functions
pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Test 1: Check if metrics endpoint is accessible
echo "Test 1: Metrics endpoint accessibility"
if curl -s -f "$METRICS_ENDPOINT" > /dev/null 2>&1; then
    pass "Metrics endpoint is accessible"
else
    fail "Metrics endpoint is NOT accessible at $METRICS_ENDPOINT"
    echo "   Please ensure the application is running"
    exit 1
fi
echo ""

# Test 2: Check if SEC-011 metrics are registered
echo "Test 2: SEC-011 metrics registration"

# Check for request_size_limit_exceeded_total
if curl -s "$METRICS_ENDPOINT" | grep -q "request_size_limit_exceeded_total"; then
    pass "request_size_limit_exceeded_total metric is registered"
else
    fail "request_size_limit_exceeded_total metric NOT found"
fi

# Check for request_body_bytes
if curl -s "$METRICS_ENDPOINT" | grep -q "request_body_bytes"; then
    pass "request_body_bytes metric is registered"
else
    fail "request_body_bytes metric NOT found"
fi
echo ""

# Test 3: Send test requests to trigger metrics
echo "Test 3: Triggering metrics with test requests"

# Test 3a: Send small valid request
echo "  3a: Sending small valid request (should succeed)"
RESPONSE=$(curl -s -w "%{http_code}" -X POST "$APP_URL/api/test" \
    -H "Content-Type: application/json" \
    -d '{"test": "data"}' \
    -o /dev/null 2>&1 || echo "000")

if [[ "$RESPONSE" == "200" ]] || [[ "$RESPONSE" == "404" ]]; then
    pass "Small request sent successfully (HTTP $RESPONSE)"
else
    warn "Small request returned HTTP $RESPONSE (expected 200 or 404)"
fi

# Test 3b: Send large request (should be rejected)
echo "  3b: Sending large request (should be rejected with 413)"
LARGE_DATA=$(python3 -c "print('A' * (11 * 1024 * 1024))")  # 11MB
RESPONSE=$(curl -s -w "%{http_code}" -X POST "$APP_URL/api/test" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 11534336" \
    -d "$LARGE_DATA" \
    -o /dev/null 2>&1 || echo "000")

if [[ "$RESPONSE" == "413" ]]; then
    pass "Large request rejected with HTTP 413 (correct)"
else
    warn "Large request returned HTTP $RESPONSE (expected 413)"
fi
echo ""

# Test 4: Verify metrics have data
echo "Test 4: Verifying metrics have collected data"

sleep 2  # Wait for metrics to update

# Check if request_body_bytes has data points
BODY_BYTES_DATA=$(curl -s "$METRICS_ENDPOINT" | grep "request_body_bytes_bucket" | head -5)
if [[ -n "$BODY_BYTES_DATA" ]]; then
    pass "request_body_bytes histogram has data points"
    echo "   Sample buckets:"
    echo "$BODY_BYTES_DATA" | head -3 | sed 's/^/   /'
else
    warn "request_body_bytes histogram has no data yet"
fi

# Check if rejections were recorded (if we sent oversized request)
REJECTION_DATA=$(curl -s "$METRICS_ENDPOINT" | grep "request_size_limit_exceeded_total" | grep -v "^#")
if [[ -n "$REJECTION_DATA" ]]; then
    pass "request_size_limit_exceeded_total counter has data"
    echo "   Sample rejections:"
    echo "$REJECTION_DATA" | head -3 | sed 's/^/   /'
else
    warn "request_size_limit_exceeded_total has no rejections yet (expected if limits not exceeded)"
fi
echo ""

# Test 5: Check Prometheus scraping (if Prometheus is available)
echo "Test 5: Prometheus integration"

if curl -s -f "$PROMETHEUS_URL/-/healthy" > /dev/null 2>&1; then
    pass "Prometheus is accessible"

    # Check if Prometheus has scraped SEC-011 metrics
    PROM_QUERY="$PROMETHEUS_URL/api/v1/query?query=request_size_limit_exceeded_total"
    PROM_RESULT=$(curl -s "$PROM_QUERY")

    if echo "$PROM_RESULT" | grep -q '"status":"success"'; then
        pass "Prometheus has request_size_limit_exceeded_total metric"
    else
        warn "Prometheus does not have request_size_limit_exceeded_total metric yet"
        echo "   This is expected if Prometheus hasn't scraped yet (wait up to scrape_interval)"
    fi

    # Check for request_body_bytes in Prometheus
    PROM_QUERY="$PROMETHEUS_URL/api/v1/query?query=request_body_bytes_bucket"
    PROM_RESULT=$(curl -s "$PROM_QUERY")

    if echo "$PROM_RESULT" | grep -q '"status":"success"'; then
        pass "Prometheus has request_body_bytes metric"
    else
        warn "Prometheus does not have request_body_bytes metric yet"
    fi
else
    warn "Prometheus is not accessible at $PROMETHEUS_URL"
    echo "   Skipping Prometheus integration tests"
fi
echo ""

# Test 6: Check alert rules (if Prometheus is available)
echo "Test 6: Alert rules validation"

if curl -s -f "$PROMETHEUS_URL/-/healthy" > /dev/null 2>&1; then
    RULES_ENDPOINT="$PROMETHEUS_URL/api/v1/rules"
    RULES_RESULT=$(curl -s "$RULES_ENDPOINT")

    if echo "$RULES_RESULT" | grep -q "HighRequestSizeRejection"; then
        pass "HighRequestSizeRejection alert rule is loaded"
    else
        warn "HighRequestSizeRejection alert rule NOT found"
    fi

    if echo "$RULES_RESULT" | grep -q "RequestSizeAttack"; then
        pass "RequestSizeAttack alert rule is loaded"
    else
        warn "RequestSizeAttack alert rule NOT found"
    fi
else
    warn "Prometheus not accessible - skipping alert rules check"
fi
echo ""

# Summary
echo "=================================================="
echo "Validation Summary"
echo "=================================================="
echo -e "Tests Passed:  ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed:  ${RED}$TESTS_FAILED${NC}"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}✓ All critical tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Check Grafana dashboard: http://grafana:3000/d/sec-011"
    echo "2. Generate load to see metrics in action"
    echo "3. Test alert rules by sending burst of oversized requests"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "1. Ensure application is running with prometheus_client installed"
    echo "2. Check application logs for metric registration errors"
    echo "3. Verify Prometheus scrape configuration"
    echo "4. Check Prometheus targets: $PROMETHEUS_URL/targets"
    exit 1
fi
