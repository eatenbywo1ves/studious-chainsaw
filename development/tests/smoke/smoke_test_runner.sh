#!/bin/bash
#
# Smoke Test Runner (Linux/macOS)
# Runs all production smoke tests and reports results
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PRODUCTION_URL="${PRODUCTION_URL:-http://localhost:8000}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=============================================================================="
echo "                    PRODUCTION SMOKE TEST RUNNER                             "
echo "=============================================================================="
echo "Target URL: ${PRODUCTION_URL}"
echo "Timestamp: ${TIMESTAMP}"
echo "=============================================================================="

# Create results directory
mkdir -p "${RESULTS_DIR}"

# Check if production URL is accessible
echo -e "\n${YELLOW}[1/4]${NC} Checking production URL accessibility..."
if curl -s -o /dev/null -w "%{http_code}" "${PRODUCTION_URL}/health" | grep -q "200\|404"; then
    echo -e "${GREEN}✓${NC} Production URL is accessible"
else
    echo -e "${RED}✗${NC} Production URL is not accessible: ${PRODUCTION_URL}"
    echo "Please verify the PRODUCTION_URL environment variable is set correctly."
    exit 1
fi

# Check Python and dependencies
echo -e "\n${YELLOW}[2/4]${NC} Checking Python environment..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗${NC} Python3 is not installed"
    exit 1
fi

if ! python3 -c "import pytest" 2>/dev/null; then
    echo -e "${YELLOW}⚠${NC} pytest not found, installing..."
    pip3 install pytest requests -q
fi

if ! python3 -c "import requests" 2>/dev/null; then
    echo -e "${YELLOW}⚠${NC} requests not found, installing..."
    pip3 install requests -q
fi

echo -e "${GREEN}✓${NC} Python environment ready"

# Run health check tests
echo -e "\n${YELLOW}[3/4]${NC} Running health check smoke tests..."
HEALTH_RESULTS="${RESULTS_DIR}/health_${TIMESTAMP}.xml"

if python3 -m pytest "${SCRIPT_DIR}/test_production_health.py" \
    --junitxml="${HEALTH_RESULTS}" \
    -v \
    --tb=short \
    --color=yes; then
    echo -e "${GREEN}✓${NC} Health check tests PASSED"
    HEALTH_STATUS="PASS"
else
    echo -e "${RED}✗${NC} Health check tests FAILED"
    HEALTH_STATUS="FAIL"
fi

# Run critical workflow tests
echo -e "\n${YELLOW}[4/4]${NC} Running critical workflow smoke tests..."
WORKFLOW_RESULTS="${RESULTS_DIR}/workflows_${TIMESTAMP}.xml"

if python3 -m pytest "${SCRIPT_DIR}/test_critical_workflows.py" \
    --junitxml="${WORKFLOW_RESULTS}" \
    -v \
    --tb=short \
    --color=yes; then
    echo -e "${GREEN}✓${NC} Workflow tests PASSED"
    WORKFLOW_STATUS="PASS"
else
    echo -e "${RED}✗${NC} Workflow tests FAILED"
    WORKFLOW_STATUS="FAIL"
fi

# Generate summary report
echo -e "\n=============================================================================="
echo "                           SMOKE TEST SUMMARY                                 "
echo "=============================================================================="
echo -e "Health Checks:        ${HEALTH_STATUS}"
echo -e "Critical Workflows:   ${WORKFLOW_STATUS}"
echo "=============================================================================="

# Save summary to file
SUMMARY_FILE="${RESULTS_DIR}/summary_${TIMESTAMP}.txt"
cat > "${SUMMARY_FILE}" << EOF
SMOKE TEST SUMMARY
==================
Timestamp: ${TIMESTAMP}
Production URL: ${PRODUCTION_URL}

Results:
--------
Health Checks:        ${HEALTH_STATUS}
Critical Workflows:   ${WORKFLOW_STATUS}

Test Results Location:
----------------------
Health Check Results:  ${HEALTH_RESULTS}
Workflow Results:      ${WORKFLOW_RESULTS}
Summary:               ${SUMMARY_FILE}

EOF

echo -e "\nResults saved to: ${RESULTS_DIR}"
echo -e "Summary: ${SUMMARY_FILE}"

# Exit with appropriate code
if [ "${HEALTH_STATUS}" = "PASS" ] && [ "${WORKFLOW_STATUS}" = "PASS" ]; then
    echo -e "\n${GREEN}✓ ALL SMOKE TESTS PASSED${NC}"
    exit 0
else
    echo -e "\n${RED}✗ SOME SMOKE TESTS FAILED${NC}"
    echo "Please review the test results before proceeding with deployment."
    exit 1
fi
