#!/bin/bash
# BMAD Verification Script
# Verifies all deployments are working correctly

set -e

echo "=========================================="
echo "BMAD DEPLOYMENT VERIFICATION"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if required variables are set
if [ -z "$DOCKER_USERNAME" ]; then
    echo "⚠️  DOCKER_USERNAME not set"
    read -p "Enter your Docker Hub username: " DOCKER_USERNAME
    export DOCKER_USERNAME
fi

# Function to test endpoint
test_endpoint() {
    local name=$1
    local url=$2
    local endpoint=$3
    
    echo "Testing $name - $endpoint..."
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url$endpoint" 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ]; then
        echo -e "${GREEN}✅ $name $endpoint - OK (200)${NC}"
        return 0
    else
        echo -e "${RED}❌ $name $endpoint - FAILED (HTTP $response)${NC}"
        return 1
    fi
}

# Test Docker Hub
echo "=========================================="
echo "1. Docker Hub Verification"
echo "=========================================="
echo ""
echo "Checking image: $DOCKER_USERNAME/go-deployment-demo:latest"
docker pull $DOCKER_USERNAME/go-deployment-demo:latest > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Docker Hub - Image accessible${NC}"
    echo "   URL: https://hub.docker.com/r/$DOCKER_USERNAME/go-deployment-demo"
else
    echo -e "${RED}❌ Docker Hub - Image not found${NC}"
fi
echo ""

# Test Local Docker Swarm
echo "=========================================="
echo "2. Local Docker Swarm Verification"
echo "=========================================="
echo ""
LOCAL_URL="http://localhost:8081"
test_endpoint "Local Swarm" "$LOCAL_URL" "/health"
test_endpoint "Local Swarm" "$LOCAL_URL" "/ready"
test_endpoint "Local Swarm" "$LOCAL_URL" "/metrics"
echo ""

# Test Railway
echo "=========================================="
echo "3. Railway.app Verification"
echo "=========================================="
echo ""
if [ -z "$RAILWAY_URL" ]; then
    echo -e "${YELLOW}⚠️  RAILWAY_URL not set${NC}"
    echo "Set it with: export RAILWAY_URL=https://your-app.up.railway.app"
    echo "Skipping Railway tests..."
else
    test_endpoint "Railway" "$RAILWAY_URL" "/health"
    test_endpoint "Railway" "$RAILWAY_URL" "/ready"
    test_endpoint "Railway" "$RAILWAY_URL" "/metrics"
    
    # Get full response
    echo ""
    echo "Railway health check response:"
    curl -s "$RAILWAY_URL/health" | jq . 2>/dev/null || curl -s "$RAILWAY_URL/health"
fi
echo ""

# Test Render
echo "=========================================="
echo "4. Render.com Verification"
echo "=========================================="
echo ""
if [ -z "$RENDER_URL" ]; then
    echo -e "${YELLOW}⚠️  RENDER_URL not set${NC}"
    echo "Set it with: export RENDER_URL=https://go-deployment-demo.onrender.com"
    echo "Skipping Render tests..."
else
    test_endpoint "Render" "$RENDER_URL" "/health"
    test_endpoint "Render" "$RENDER_URL" "/ready"
    test_endpoint "Render" "$RENDER_URL" "/metrics"
    
    # Get full response
    echo ""
    echo "Render health check response:"
    curl -s "$RENDER_URL/health" | jq . 2>/dev/null || curl -s "$RENDER_URL/health"
fi
echo ""

# Summary
echo "=========================================="
echo "VERIFICATION SUMMARY"
echo "=========================================="
echo ""
echo "Deployment Status:"
echo "  ✅ Docker Hub - Image available"
echo "  ✅ Local Swarm - Running (if tested successfully)"
if [ ! -z "$RAILWAY_URL" ]; then
    echo "  ✅ Railway - Deployed (if tests passed)"
fi
if [ ! -z "$RENDER_URL" ]; then
    echo "  ✅ Render - Deployed (if tests passed)"
fi
echo ""
echo "To set deployment URLs:"
echo "  export RAILWAY_URL=https://your-app.up.railway.app"
echo "  export RENDER_URL=https://go-deployment-demo.onrender.com"
echo ""
echo "Then run this script again to verify cloud deployments."
echo ""
