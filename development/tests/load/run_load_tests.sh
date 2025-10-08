#!/bin/bash
# ============================================================================
# Load Testing Runner - Linux/Mac Shell Script
# Catalytic Computing SaaS Platform
# ============================================================================

set -e  # Exit on error

echo ""
echo "==============================================================================="
echo "CATALYTIC COMPUTING SAAS - LOAD TESTING RUNNER (Linux/Mac)"
echo "==============================================================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.8+ from your package manager"
    exit 1
fi

# Check if Locust is installed
if ! python3 -c "import locust" &> /dev/null; then
    echo "ERROR: Locust is not installed"
    echo "Installing dependencies..."
    pip install -r requirements.txt || {
        echo "ERROR: Failed to install dependencies"
        exit 1
    }
fi

# Default configuration
HOST="${2:-http://localhost:8000}"
SCENARIO="${1:-all}"

echo "Starting load tests..."
echo "Host: $HOST"
echo "Scenario: $SCENARIO"
echo ""

# Run the test runner
python3 run_load_tests.py --host "$HOST" --scenario "$SCENARIO"

echo ""
echo "==============================================================================="
echo "Load testing complete! Check the results/ directory for reports."
echo "==============================================================================="
echo ""
