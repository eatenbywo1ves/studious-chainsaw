#!/bin/bash
# Start Catalytic Computing SaaS Platform

set -e

echo "=================================="
echo "Starting Catalytic Computing SaaS"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found!${NC}"
    echo "Please create .env file from .env.example"
    exit 1
fi

# Load environment variables
set -a
source .env 2>/dev/null || true
set +a

echo -e "${YELLOW}Checking Docker...${NC}"
docker --version
docker-compose version

# Stop any conflicting services on required ports
echo -e "${YELLOW}Checking port availability...${NC}"
PORTS=(5432 8000 8001 9090 3000 80 443)
for PORT in "${PORTS[@]}"; do
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning: Port $PORT is already in use${NC}"
    fi
done

# Pull required images
echo -e "${YELLOW}Pulling Docker images...${NC}"
docker pull postgres:15-alpine
docker pull redis:7-alpine
docker pull prom/prometheus:latest
docker pull grafana/grafana:latest
docker pull nginx:alpine

# Build custom images if needed
if [ "$1" == "--build" ] || [ ! "$(docker images -q catalytic-saas:latest 2> /dev/null)" ]; then
    echo -e "${YELLOW}Building SaaS Docker image...${NC}"
    docker build -f Dockerfile.saas -t catalytic-saas:latest .
fi

# Create necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p logs/saas logs/webhooks logs/workers keys ssl

# Generate JWT keys if they don't exist
if [ ! -f keys/jwt_private.pem ] || [ ! -f keys/jwt_public.pem ]; then
    echo -e "${YELLOW}Generating JWT RSA keys...${NC}"
    openssl genrsa -out keys/jwt_private.pem 2048
    openssl rsa -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem
    chmod 600 keys/jwt_private.pem
    echo -e "${GREEN}JWT keys generated successfully${NC}"
fi

# Start the services
echo -e "${YELLOW}Starting Docker Compose stack...${NC}"
docker-compose -f docker-compose-saas.yml up -d

# Wait for PostgreSQL to be ready
echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
for i in {1..30}; do
    if docker exec catalytic-postgres pg_isready -U catalytic >/dev/null 2>&1; then
        echo -e "${GREEN}PostgreSQL is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# Initialize database if needed
echo -e "${YELLOW}Initializing database...${NC}"
docker exec catalytic-postgres psql -U catalytic -d catalytic_saas -c "SELECT 1 FROM subscription_plans LIMIT 1;" >/dev/null 2>&1 || {
    echo -e "${YELLOW}Creating database schema...${NC}"
    docker exec -i catalytic-postgres psql -U catalytic -d catalytic_saas < saas/database/schema.sql
}

# Check service health
echo -e "${YELLOW}Checking service health...${NC}"
sleep 5

SERVICES=("catalytic-postgres" "catalytic-redis" "catalytic-saas-api" "catalytic-webhooks" "catalytic-prometheus" "catalytic-grafana")
ALL_HEALTHY=true

for SERVICE in "${SERVICES[@]}"; do
    if docker ps --filter "name=$SERVICE" --filter "status=running" | grep -q $SERVICE; then
        echo -e "${GREEN}✓ $SERVICE is running${NC}"
    else
        echo -e "${RED}✗ $SERVICE is not running${NC}"
        ALL_HEALTHY=false
    fi
done

if $ALL_HEALTHY; then
    echo -e "${GREEN}=================================="
    echo "All services started successfully!"
    echo "=================================="
    echo ""
    echo "Access points:"
    echo "  API:       http://localhost:8000"
    echo "  Docs:      http://localhost:8000/docs"
    echo "  Grafana:   http://localhost:3000 (admin / ${GRAFANA_PASSWORD})"
    echo "  Prometheus: http://localhost:9090"
    echo ""
    echo "To view logs: docker-compose -f docker-compose-saas.yml logs -f"
    echo "To stop:     ./scripts/stop-saas.sh"
else
    echo -e "${RED}Some services failed to start. Check logs:${NC}"
    echo "docker-compose -f docker-compose-saas.yml logs"
    exit 1
fi