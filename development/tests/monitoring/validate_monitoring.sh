#!/bin/bash
# ============================================================================
# Automated Monitoring Validation Script (Linux/Mac)
#
# This script runs all monitoring validation tests to ensure the monitoring
# infrastructure is working correctly.
# ============================================================================

set -e

echo "============================================================================"
echo "CATALYTIC SAAS - MONITORING VALIDATION"
echo "============================================================================"
echo ""

# Set working directory
cd "$(dirname "$0")"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python is not installed"
    exit 1
fi

# Check if pytest is installed
if ! python3 -c "import pytest" &> /dev/null; then
    echo "Installing pytest..."
    pip3 install pytest requests
fi

TEST_FAILED=0

echo "[1/4] Testing Prometheus scraping..."
echo ""
if python3 test_prometheus_scraping.py; then
    echo "PASSED: Prometheus scraping validation"
else
    echo "FAILED: Prometheus scraping validation failed"
    TEST_FAILED=1
fi
echo ""

echo "[2/4] Testing Grafana dashboards..."
echo ""
if python3 test_grafana_dashboards.py; then
    echo "PASSED: Grafana dashboard validation"
else
    echo "FAILED: Grafana dashboard validation failed"
    TEST_FAILED=1
fi
echo ""

echo "[3/4] Testing alert rules..."
echo ""
if python3 test_alert_rules.py; then
    echo "PASSED: Alert rules validation"
else
    echo "FAILED: Alert rules validation failed"
    TEST_FAILED=1
fi
echo ""

echo "[4/4] Running pytest suite..."
echo ""
if pytest -v --tb=short; then
    echo "PASSED: Pytest suite validation"
else
    echo "FAILED: Pytest suite validation failed"
    TEST_FAILED=1
fi
echo ""

echo "============================================================================"
if [ $TEST_FAILED -eq 1 ]; then
    echo "RESULT: SOME VALIDATIONS FAILED"
    echo "============================================================================"
    exit 1
else
    echo "RESULT: ALL VALIDATIONS PASSED"
    echo "============================================================================"
    exit 0
fi
