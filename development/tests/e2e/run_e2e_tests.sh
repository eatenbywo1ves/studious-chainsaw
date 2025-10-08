#!/bin/bash
# E2E Test Runner for Linux/Mac
# Manages E2E test environment and execution

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  E2E Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Step 1: Start E2E environment
echo -e "${YELLOW}[1/6] Starting E2E test environment...${NC}"
docker compose -f docker-compose.e2e.yml up -d

# Step 2: Wait for services
echo -e "${YELLOW}[2/6] Waiting for services to be ready...${NC}"
echo "Waiting 40 seconds for all services to initialize..."
sleep 40

# Check service health
echo "Checking service health..."
docker compose -f docker-compose.e2e.yml ps

# Step 3: Run E2E tests
echo ""
echo -e "${YELLOW}[3/6] Running E2E tests...${NC}"

# Parse arguments
REPORT_HTML=""
VERBOSE="-v"
TEST_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            REPORT_HTML="--html=e2e_report.html --self-contained-html"
            shift
            ;;
        --filter)
            TEST_FILTER="-k $2"
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

# Set E2E environment variables
export E2E_API_URL="http://localhost:8002"
export E2E_TIMEOUT=60

# Run tests
if [ -n "$TEST_FILTER" ]; then
    echo "Running filtered E2E tests: $TEST_FILTER"
    pytest $VERBOSE $REPORT_HTML $TEST_FILTER || E2E_EXIT_CODE=$?
else
    echo "Running all E2E tests..."
    pytest $VERBOSE $REPORT_HTML || E2E_EXIT_CODE=$?
fi

# Step 4: Show results
echo ""
echo -e "${YELLOW}[4/6] Test Results${NC}"

if [ "${E2E_EXIT_CODE:-0}" -eq 0 ]; then
    echo -e "${GREEN}✓ All E2E tests passed!${NC}"
else
    echo -e "${RED}✗ Some E2E tests failed (exit code: $E2E_EXIT_CODE)${NC}"
fi

# Step 5: Show logs if tests failed
if [ "${E2E_EXIT_CODE:-0}" -ne 0 ]; then
    echo ""
    echo -e "${YELLOW}[5/6] Showing service logs...${NC}"
    docker compose -f docker-compose.e2e.yml logs --tail=50 saas-api-e2e
fi

# Step 6: Cleanup
echo ""
echo -e "${YELLOW}[6/6] Cleanup${NC}"
read -p "Stop E2E environment? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Stopping E2E environment..."
    docker compose -f docker-compose.e2e.yml down
    echo -e "${GREEN}✓ E2E environment stopped${NC}"
else
    echo "E2E environment still running. Stop manually with:"
    echo "  docker compose -f docker-compose.e2e.yml down"
fi

# Show HTML report location
if [ -n "$REPORT_HTML" ] && [ -f "e2e_report.html" ]; then
    echo ""
    echo "HTML report generated: e2e_report.html"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  E2E Test Run Complete${NC}"
echo -e "${BLUE}========================================${NC}"

exit ${E2E_EXIT_CODE:-0}
