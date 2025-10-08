#!/usr/bin/env bash
#
# Complete Phase 1 Deployment Script
# Deploys Redis and verifies security system integration
#

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$SECURITY_DIR")"
SAAS_DIR="$PROJECT_ROOT/saas"

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  Phase 1 Deployment - Complete Redis Integration${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

# Step 1: Check Docker
echo -e "${YELLOW}[1/6] Checking Docker...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found!${NC}"
    echo "Please install Docker Desktop and try again."
    exit 1
fi

if ! docker ps &> /dev/null; then
    echo -e "${RED}✗ Docker daemon not running!${NC}"
    echo "Please start Docker Desktop and try again."
    exit 1
fi

echo -e "${GREEN}✓ Docker is running${NC}"
echo ""

# Step 2: Deploy Redis
echo -e "${YELLOW}[2/6] Deploying Redis service...${NC}"
cd "$SAAS_DIR"

if docker ps | grep -q catalytic-redis; then
    echo -e "${YELLOW}⚠ Redis already running, restarting...${NC}"
    docker-compose -f docker-compose.redis.yml restart
else
    docker-compose -f docker-compose.redis.yml up -d
fi

echo -e "${GREEN}✓ Redis container started${NC}"
echo ""

# Step 3: Verify Redis
echo -e "${YELLOW}[3/6] Verifying Redis connection...${NC}"
sleep 3  # Wait for Redis to initialize

if docker exec catalytic-redis redis-cli ping | grep -q PONG; then
    echo -e "${GREEN}✓ Redis is responding${NC}"
else
    echo -e "${RED}✗ Redis not responding!${NC}"
    echo "Check logs: docker logs catalytic-redis"
    exit 1
fi

# Check Redis info
echo ""
echo -e "${BLUE}Redis Information:${NC}"
docker exec catalytic-redis redis-cli INFO server | grep -E "redis_version|os|uptime_in_seconds"
echo ""

# Step 4: Check Security Keys
echo -e "${YELLOW}[4/6] Checking security keys...${NC}"
PRIVATE_KEY="$SECURITY_DIR/keys/jwt_development_private.pem"
PUBLIC_KEY="$SECURITY_DIR/keys/jwt_development_public.pem"

if [ ! -f "$PRIVATE_KEY" ] || [ ! -f "$PUBLIC_KEY" ]; then
    echo -e "${YELLOW}⚠ Keys not found, generating...${NC}"
    bash "$SCRIPT_DIR/01-setup-keys.sh" development
fi

if [ -f "$PRIVATE_KEY" ] && [ -f "$PUBLIC_KEY" ]; then
    echo -e "${GREEN}✓ Security keys present${NC}"
else
    echo -e "${RED}✗ Failed to generate keys!${NC}"
    exit 1
fi
echo ""

# Step 5: Run Integration Tests
echo -e "${YELLOW}[5/6] Running integration tests...${NC}"
cd "$SECURITY_DIR"

if command -v pytest &> /dev/null; then
    echo "Running pytest..."
    python -m pytest tests/test_redis_integration.py -v --tb=short
    TEST_RESULT=$?

    if [ $TEST_RESULT -eq 0 ]; then
        echo -e "${GREEN}✓ All integration tests passed${NC}"
    else
        echo -e "${RED}✗ Some tests failed (exit code: $TEST_RESULT)${NC}"
        echo "Review test output above for details"
    fi
else
    echo -e "${YELLOW}⚠ pytest not found, skipping tests${NC}"
    echo "Install with: pip install pytest"
fi
echo ""

# Step 6: Display Next Steps
echo -e "${YELLOW}[6/6] Deployment Summary${NC}"
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}  ✓ Phase 1 Deployment Complete!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${BLUE}Services Running:${NC}"
docker ps --filter "name=catalytic-redis" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo ""
echo -e "1. ${YELLOW}Start the application:${NC}"
echo "   cd $SAAS_DIR/api"
echo "   python saas_server.py"
echo ""
echo -e "2. ${YELLOW}Test health endpoints:${NC}"
echo "   curl http://localhost:8000/health"
echo "   curl http://localhost:8000/security/health"
echo ""
echo -e "3. ${YELLOW}Enable new security system (optional):${NC}"
echo "   Edit $SAAS_DIR/.env"
echo "   Add: USE_NEW_SECURITY=true"
echo "   Restart application"
echo ""
echo -e "4. ${YELLOW}Monitor Redis:${NC}"
echo "   docker exec -it catalytic-redis redis-cli MONITOR"
echo ""
echo -e "5. ${YELLOW}View deployment guide:${NC}"
echo "   cat $SECURITY_DIR/deployment/REDIS_DEPLOYMENT_GUIDE.md"
echo ""

echo -e "${BLUE}Redis Management:${NC}"
echo -e "  Stop:    ${NC}docker-compose -f $SAAS_DIR/docker-compose.redis.yml down"
echo -e "  Restart: ${NC}docker-compose -f $SAAS_DIR/docker-compose.redis.yml restart"
echo -e "  Logs:    ${NC}docker logs catalytic-redis"
echo ""

echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}For detailed documentation, see:${NC}"
echo -e "  ${NC}$PROJECT_ROOT/PHASE1_COMPLETION_SUMMARY.md"
echo -e "${GREEN}================================================================${NC}"
