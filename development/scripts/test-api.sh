#!/bin/bash
# Test Catalytic Computing SaaS API

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL=${API_URL:-"http://localhost:8000"}

echo "===================================="
echo "Testing Catalytic Computing SaaS API"
echo "===================================="
echo ""

# Function to make API calls
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local token=$4

    if [ -n "$token" ]; then
        if [ -n "$data" ]; then
            curl -s -X $method \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $token" \
                -d "$data" \
                "$API_URL$endpoint"
        else
            curl -s -X $method \
                -H "Authorization: Bearer $token" \
                "$API_URL$endpoint"
        fi
    else
        if [ -n "$data" ]; then
            curl -s -X $method \
                -H "Content-Type: application/json" \
                -d "$data" \
                "$API_URL$endpoint"
        else
            curl -s -X $method "$API_URL$endpoint"
        fi
    fi
}

# Test 1: Health Check
echo -e "${YELLOW}Test 1: Health Check${NC}"
response=$(api_call GET /health)
if echo "$response" | grep -q "healthy"; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${RED}✗ Health check failed${NC}"
    echo "Response: $response"
    exit 1
fi
echo ""

# Test 2: Register Tenant
echo -e "${YELLOW}Test 2: Register New Tenant${NC}"
TIMESTAMP=$(date +%s)
TENANT_DATA='{
    "company_name": "Test Company '$TIMESTAMP'",
    "email": "test'$TIMESTAMP'@example.com",
    "password": "TestPassword123!",
    "first_name": "Test",
    "last_name": "User",
    "plan_code": "free"
}'

response=$(api_call POST /api/tenants/register "$TENANT_DATA")
if echo "$response" | grep -q "tenant"; then
    echo -e "${GREEN}✓ Tenant registration successful${NC}"

    # Extract tokens
    ACCESS_TOKEN=$(echo "$response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    REFRESH_TOKEN=$(echo "$response" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

    if [ -n "$ACCESS_TOKEN" ]; then
        echo -e "${BLUE}Access token received (first 20 chars): ${ACCESS_TOKEN:0:20}...${NC}"
    fi
else
    echo -e "${RED}✗ Tenant registration failed${NC}"
    echo "Response: $response"
    exit 1
fi
echo ""

# Test 3: Login
echo -e "${YELLOW}Test 3: Login${NC}"
LOGIN_DATA='{
    "email": "test'$TIMESTAMP'@example.com",
    "password": "TestPassword123!"
}'

response=$(api_call POST /auth/login "$LOGIN_DATA")
if echo "$response" | grep -q "access_token"; then
    echo -e "${GREEN}✓ Login successful${NC}"

    # Update token from login
    ACCESS_TOKEN=$(echo "$response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
else
    echo -e "${RED}✗ Login failed${NC}"
    echo "Response: $response"
fi
echo ""

# Test 4: Create Lattice
echo -e "${YELLOW}Test 4: Create Lattice${NC}"
LATTICE_DATA='{
    "name": "Test Lattice",
    "dimensions": 3,
    "size": 5
}'

response=$(api_call POST /api/lattices "$LATTICE_DATA" "$ACCESS_TOKEN")
if echo "$response" | grep -q "id"; then
    echo -e "${GREEN}✓ Lattice created successfully${NC}"

    # Extract lattice ID
    LATTICE_ID=$(echo "$response" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
    echo -e "${BLUE}Lattice ID: $LATTICE_ID${NC}"

    # Check memory reduction
    MEMORY_REDUCTION=$(echo "$response" | grep -o '"memory_reduction":[0-9.]*' | cut -d':' -f2)
    if [ -n "$MEMORY_REDUCTION" ]; then
        echo -e "${BLUE}Memory reduction: ${MEMORY_REDUCTION}x${NC}"
    fi
else
    echo -e "${RED}✗ Lattice creation failed${NC}"
    echo "Response: $response"
fi
echo ""

# Test 5: List Lattices
echo -e "${YELLOW}Test 5: List Lattices${NC}"
response=$(api_call GET /api/lattices "" "$ACCESS_TOKEN")
if echo "$response" | grep -q "\["; then
    echo -e "${GREEN}✓ Lattices listed successfully${NC}"

    # Count lattices
    LATTICE_COUNT=$(echo "$response" | grep -o '"id"' | wc -l)
    echo -e "${BLUE}Number of lattices: $LATTICE_COUNT${NC}"
else
    echo -e "${RED}✗ Failed to list lattices${NC}"
    echo "Response: $response"
fi
echo ""

# Test 6: Path Finding (if lattice was created)
if [ -n "$LATTICE_ID" ]; then
    echo -e "${YELLOW}Test 6: Path Finding${NC}"
    PATH_DATA='{
        "lattice_id": "'$LATTICE_ID'",
        "start": [0, 0, 0],
        "end": [4, 4, 4]
    }'

    response=$(api_call POST /api/lattices/path "$PATH_DATA" "$ACCESS_TOKEN")
    if echo "$response" | grep -q "path"; then
        echo -e "${GREEN}✓ Path finding successful${NC}"

        # Extract execution time
        EXEC_TIME=$(echo "$response" | grep -o '"execution_time_ms":[0-9.]*' | cut -d':' -f2)
        if [ -n "$EXEC_TIME" ]; then
            echo -e "${BLUE}Execution time: ${EXEC_TIME}ms${NC}"
        fi
    else
        echo -e "${RED}✗ Path finding failed${NC}"
        echo "Response: $response"
    fi
    echo ""
fi

# Test 7: Get Current Tenant Info
echo -e "${YELLOW}Test 7: Get Current Tenant${NC}"
response=$(api_call GET /api/tenants/current "" "$ACCESS_TOKEN")
if echo "$response" | grep -q "subscription_plan"; then
    echo -e "${GREEN}✓ Tenant info retrieved${NC}"

    # Extract subscription plan
    PLAN=$(echo "$response" | grep -o '"subscription_plan":"[^"]*' | cut -d'"' -f4)
    echo -e "${BLUE}Subscription plan: $PLAN${NC}"
else
    echo -e "${RED}✗ Failed to get tenant info${NC}"
    echo "Response: $response"
fi
echo ""

# Test 8: Create API Key
echo -e "${YELLOW}Test 8: Create API Key${NC}"
API_KEY_DATA='{
    "name": "Test API Key",
    "permissions": ["read", "write"],
    "expires_in_days": 30
}'

response=$(api_call POST /api/tenants/api-keys "$API_KEY_DATA" "$ACCESS_TOKEN")
if echo "$response" | grep -q "key"; then
    echo -e "${GREEN}✓ API key created${NC}"

    # Extract API key
    API_KEY=$(echo "$response" | grep -o '"key":"[^"]*' | cut -d'"' -f4)
    if [ -n "$API_KEY" ]; then
        echo -e "${BLUE}API key (first 20 chars): ${API_KEY:0:20}...${NC}"
    fi
else
    echo -e "${RED}✗ API key creation failed${NC}"
    echo "Response: $response"
fi
echo ""

# Test 9: Get Usage Stats
echo -e "${YELLOW}Test 9: Get Usage Stats${NC}"
response=$(api_call GET /api/tenants/usage "" "$ACCESS_TOKEN")
if echo "$response" | grep -q "api_calls"; then
    echo -e "${GREEN}✓ Usage stats retrieved${NC}"

    # Extract stats
    API_CALLS=$(echo "$response" | grep -o '"api_calls":[0-9]*' | cut -d':' -f2)
    LATTICES_ACTIVE=$(echo "$response" | grep -o '"lattices_active":[0-9]*' | cut -d':' -f2)
    COST=$(echo "$response" | grep -o '"cost_estimate":[0-9.]*' | cut -d':' -f2)

    echo -e "${BLUE}API calls: $API_CALLS${NC}"
    echo -e "${BLUE}Active lattices: $LATTICES_ACTIVE${NC}"
    echo -e "${BLUE}Estimated cost: \$$COST${NC}"
else
    echo -e "${RED}✗ Failed to get usage stats${NC}"
    echo "Response: $response"
fi
echo ""

# Test 10: API Documentation Check
echo -e "${YELLOW}Test 10: API Documentation${NC}"
response=$(api_call GET /docs)
if echo "$response" | grep -q "swagger-ui"; then
    echo -e "${GREEN}✓ API documentation available at $API_URL/docs${NC}"
else
    echo -e "${YELLOW}⚠ API documentation may not be available${NC}"
fi
echo ""

# Summary
echo "===================================="
echo -e "${GREEN}API Testing Complete!${NC}"
echo "===================================="
echo ""
echo "Access Points:"
echo "  API Docs: $API_URL/docs"
echo "  Health: $API_URL/health"
echo ""
echo "Test Token (for manual testing):"
echo "  $ACCESS_TOKEN"
echo ""