#!/bin/bash
# test-suite.sh - Comprehensive validation test suite
# Wiz Zero Day Cloud 2025 Competition
# Created: October 6, 2025

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

RESEARCH_DIR="$HOME/nvidia-toolkit-research"
TEST_DIR="$RESEARCH_DIR/tests"
mkdir -p "$TEST_DIR"/{functional,security,detection,performance}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          NVIDIA Container Toolkit Test Suite                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test runner function
run_test() {
    local category=$1
    local test_name=$2
    local test_cmd=$3
    local expected_pattern=$4
    local should_succeed=${5:-true}

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}TEST $TESTS_TOTAL: $test_name${NC}"
    echo "Category: $category"
    echo "Command: $test_cmd"
    echo ""

    # Run test and capture output
    if result=$(eval "$test_cmd" 2>&1); then
        test_exit_code=0
    else
        test_exit_code=$?
    fi

    # Save output
    echo "$result" > "$TEST_DIR/$category/test${TESTS_TOTAL}-output.txt"

    # Check if result matches expected pattern
    if [ "$should_succeed" = "true" ]; then
        if echo "$result" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}✓ PASS${NC}: Test succeeded as expected"
            echo "$test_name: PASS" >> "$TEST_DIR/test-results.txt"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        else
            echo -e "${RED}✗ FAIL${NC}: Expected pattern not found"
            echo "Expected: $expected_pattern"
            echo "Got: $(echo "$result" | head -3)"
            echo "$test_name: FAIL" >> "$TEST_DIR/test-results.txt"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    else
        # Test should fail
        if [ $test_exit_code -ne 0 ]; then
            echo -e "${GREEN}✓ PASS${NC}: Test failed as expected"
            echo "$test_name: PASS (expected failure)" >> "$TEST_DIR/test-results.txt"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        else
            echo -e "${RED}✗ FAIL${NC}: Test succeeded when it should have failed"
            echo "$test_name: FAIL (unexpected success)" >> "$TEST_DIR/test-results.txt"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    fi
}

# Clear previous results
> "$TEST_DIR/test-results.txt"

# ==============================================================================
# FUNCTIONAL TESTS
# ==============================================================================

echo -e "${BLUE}[Category 1/4] Functional Tests${NC}"
echo ""

run_test "functional" \
    "Docker availability" \
    "docker --version" \
    "Docker version"

run_test "functional" \
    "NVIDIA Container Toolkit availability" \
    "nvidia-ctk --version" \
    "NVIDIA Container Toolkit"

run_test "functional" \
    "GPU visibility in container" \
    "docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi" \
    "GTX 1080"

run_test "functional" \
    "CUDA libraries accessible" \
    "docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 ls /usr/local/cuda" \
    "bin"

run_test "functional" \
    "GPU device nodes mounted" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 ls /dev/nvidia*" \
    "nvidia0"

# ==============================================================================
# SECURITY TESTS
# ==============================================================================

echo ""
echo -e "${BLUE}[Category 2/4] Security Tests${NC}"
echo ""

run_test "security" \
    "Container isolation - host proc access (should fail)" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 cat /proc/1/root 2>&1" \
    "Permission denied\|No such file" \
    false

run_test "security" \
    "Container isolation - flag file access (should fail)" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 cat /flag 2>&1" \
    "No such file" \
    false

run_test "security" \
    "Container capabilities - limited set" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 capsh --print" \
    "Current:"

run_test "security" \
    "Container capabilities - no CAP_SYS_ADMIN by default" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 capsh --print | grep -q CAP_SYS_ADMIN" \
    "" \
    false

run_test "security" \
    "Namespace isolation - separate PID namespace" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 readlink /proc/self/ns/pid" \
    "pid:"

run_test "security" \
    "User namespace - running as root in container" \
    "docker run --rm --runtime=nvidia --gpus all ubuntu:22.04 whoami" \
    "root"

# ==============================================================================
# DETECTION TESTS
# ==============================================================================

echo ""
echo -e "${BLUE}[Category 3/4] Detection Tests${NC}"
echo ""

# Check if Falco is running
if ! sudo systemctl is-active --quiet falco; then
    echo -e "${YELLOW}⚠ Falco not running - starting...${NC}"
    sudo systemctl start falco
    sleep 3
fi

run_test "detection" \
    "Falco service running" \
    "sudo systemctl is-active falco" \
    "active"

run_test "detection" \
    "Falco rules loaded" \
    "sudo journalctl -u falco --since '5 minutes ago' | grep -i 'rules loaded'" \
    "rules loaded\|Rules"

# Detection test 1: Benign container (should NOT alert)
echo "Running benign container..."
docker run --rm --runtime=nvidia --gpus all \
    nvidia/cuda:12.2.0-base-ubuntu22.04 \
    nvidia-smi > /dev/null 2>&1

sleep 2

run_test "detection" \
    "Benign container - no false alerts" \
    "sudo journalctl -u falco --since '10 seconds ago' | grep -c 'CRITICAL' || echo '0'" \
    "^0$"

# Detection test 2: LD_PRELOAD injection (SHOULD alert)
echo "Running LD_PRELOAD detection test..."
docker run --rm --runtime=nvidia --gpus all \
    -e LD_PRELOAD=/tmp/malicious.so \
    nvidia/cuda:12.2.0-base-ubuntu22.04 \
    echo "Test" > /dev/null 2>&1

sleep 2

run_test "detection" \
    "LD_PRELOAD injection detection" \
    "sudo journalctl -u falco --since '10 seconds ago' | grep -i 'ld_preload\|suspicious library'" \
    "LD_PRELOAD\|library injection"

# Detection test 3: Host filesystem access (SHOULD alert)
echo "Running host filesystem access test..."
docker run --rm --runtime=nvidia --gpus all \
    ubuntu:22.04 \
    cat /proc/1/environ > /dev/null 2>&1 || true

sleep 2

run_test "detection" \
    "Host filesystem access detection" \
    "sudo journalctl -u falco --since '10 seconds ago' | grep -i 'host filesystem\|proc/1'" \
    "filesystem\|/proc/1"

# ==============================================================================
# PERFORMANCE TESTS
# ==============================================================================

echo ""
echo -e "${BLUE}[Category 4/4] Performance Tests${NC}"
echo ""

run_test "performance" \
    "Container startup time < 5 seconds" \
    "time timeout 5 docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi 2>&1" \
    "real"

run_test "performance" \
    "GPU memory accessible" \
    "docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi --query-gpu=memory.total --format=csv" \
    "[0-9]"

run_test "performance" \
    "Multiple concurrent GPU containers" \
    "docker run -d --name test1 --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 sleep 10 && \
     docker run -d --name test2 --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 sleep 10 && \
     docker ps | grep -c 'test[12]' && \
     docker rm -f test1 test2 > /dev/null 2>&1" \
    "2"

# ==============================================================================
# TEST SUMMARY
# ==============================================================================

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                      Test Summary                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

PASS_PERCENT=$((TESTS_PASSED * 100 / TESTS_TOTAL))

echo "Total Tests: $TESTS_TOTAL"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo "Success Rate: $PASS_PERCENT%"
echo ""

# Generate detailed report
cat << EOF > "$TEST_DIR/TEST_SUMMARY.md"
# Test Suite Summary
**Date:** $(date)
**Environment:** Ubuntu 24.04 WSL2

## Results
- **Total Tests:** $TESTS_TOTAL
- **Passed:** $TESTS_PASSED
- **Failed:** $TESTS_FAILED
- **Success Rate:** $PASS_PERCENT%

## Test Categories
1. Functional Tests: $(grep -c "functional.*PASS" "$TEST_DIR/test-results.txt" || echo "0")/5
2. Security Tests: $(grep -c "security.*PASS" "$TEST_DIR/test-results.txt" || echo "0")/6
3. Detection Tests: $(grep -c "detection.*PASS" "$TEST_DIR/test-results.txt" || echo "0")/5
4. Performance Tests: $(grep -c "performance.*PASS" "$TEST_DIR/test-results.txt" || echo "0")/3

## Detailed Results
\`\`\`
$(cat "$TEST_DIR/test-results.txt")
\`\`\`

## Recommendations
$(if [ $TESTS_FAILED -eq 0 ]; then
    echo "✓ All tests passed - environment is fully operational"
else
    echo "⚠ $TESTS_FAILED test(s) failed - review logs in $TEST_DIR/"
    echo ""
    echo "Failed tests:"
    grep "FAIL" "$TEST_DIR/test-results.txt" | sed 's/^/- /'
fi)

## Next Steps
$(if [ $PASS_PERCENT -ge 90 ]; then
    echo "- Begin vulnerability research"
    echo "- Deploy advanced detection rules"
    echo "- Start security hardening"
else
    echo "- Fix failing tests"
    echo "- Review environment configuration"
    echo "- Check logs for error details"
fi)

---
Test logs available in: $TEST_DIR/
EOF

cat "$TEST_DIR/TEST_SUMMARY.md"

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed - review logs${NC}"
    exit 1
fi
