#!/bin/bash
# Stop Catalytic Computing SaaS Platform

set -e

echo "=================================="
echo "Stopping Catalytic Computing SaaS"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Stop services
echo -e "${YELLOW}Stopping Docker Compose stack...${NC}"
docker-compose -f docker-compose-saas.yml down

# Optional: Remove volumes (only if --clean flag is passed)
if [ "$1" == "--clean" ]; then
    echo -e "${YELLOW}Removing volumes...${NC}"
    docker-compose -f docker-compose-saas.yml down -v

    echo -e "${YELLOW}Removing generated files...${NC}"
    rm -rf keys/jwt_*.pem

    echo -e "${GREEN}Clean shutdown complete${NC}"
else
    echo -e "${GREEN}Services stopped (volumes preserved)${NC}"
    echo "To remove volumes as well, run: $0 --clean"
fi

echo -e "${GREEN}=================================="
echo "SaaS platform stopped successfully"
echo "==================================${NC}"