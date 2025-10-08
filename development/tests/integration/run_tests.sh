#!/bin/bash
# Integration Test Runner
# Automates starting test environment, running tests, and cleanup

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Integration Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Step 1: Start test environment
echo -e "${YELLOW}[1/5] Starting test environment...${NC}"
docker compose -f docker-compose.test.yml up -d

# Step 2: Wait for services to be healthy
echo -e "${YELLOW}[2/5] Waiting for services to be healthy...${NC}"
echo "Waiting 30 seconds for services to initialize..."
sleep 30

# Check service health
echo "Checking service health..."
docker compose -f docker-compose.test.yml ps

# Step 3: Run tests
echo ""
echo -e "${YELLOW}[3/5] Running integration tests...${NC}"

# Parse command line arguments
TEST_FILTER=""
COVERAGE=""
VERBOSE="-v"

while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            COVERAGE="--cov=saas --cov=apps/catalytic --cov-report=html --cov-report=term"
            shift
            ;;
        --filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        --quiet)
            VERBOSE=""
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run pytest
if [ -n "$TEST_FILTER" ]; then
    echo "Running filtered tests: $TEST_FILTER"
    pytest $VERBOSE $COVERAGE -k "$TEST_FILTER" || TEST_EXIT_CODE=$?
else
    echo "Running all integration tests..."
    pytest $VERBOSE $COVERAGE || TEST_EXIT_CODE=$?
fi

# Step 4: Show results
echo ""
echo -e "${YELLOW}[4/5] Test Results${NC}"

if [ "${TEST_EXIT_CODE:-0}" -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${RED}✗ Some tests failed (exit code: $TEST_EXIT_CODE)${NC}"
fi

# Step 5: Cleanup
echo ""
echo -e "${YELLOW}[5/5] Cleanup${NC}"
read -p "Stop test environment? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Stopping test environment..."
    docker compose -f docker-compose.test.yml down
    echo -e "${GREEN}✓ Test environment stopped${NC}"
else
    echo "Test environment still running. Stop manually with:"
    echo "  docker compose -f docker-compose.test.yml down"
fi

# Show coverage report if generated
if [ -n "$COVERAGE" ] && [ -d "htmlcov" ]; then
    echo ""
    echo "Coverage report generated: htmlcov/index.html"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Integration Test Run Complete${NC}"
echo -e "${BLUE}========================================${NC}"

exit ${TEST_EXIT_CODE:-0}
