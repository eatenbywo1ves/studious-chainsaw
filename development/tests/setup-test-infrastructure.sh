#!/bin/bash

###############################################################################
# Test Infrastructure Setup Script
# Purpose: Automated setup of test environment for 87 integration tests
# Author: BMAD DevOps Agent
# Date: 2025-10-06
###############################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"
INTEGRATION_DIR="$TESTS_DIR/integration"
DOCKER_COMPOSE_FILE="$INTEGRATION_DIR/docker-compose.test.yml"
ENV_FILE="$INTEGRATION_DIR/.env.test"

# Service health check timeout (seconds)
HEALTH_CHECK_TIMEOUT=60
HEALTH_CHECK_INTERVAL=5

###############################################################################
# Pre-flight Checks
###############################################################################

log_info "Starting test infrastructure setup..."
echo "=================================================="

# Check Docker is installed
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker and try again."
    exit 1
fi

# Check Docker Compose is available
if ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not available. Please install Docker Compose V2."
    exit 1
fi

# Check if docker-compose.test.yml exists
if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
    log_error "docker-compose.test.yml not found at: $DOCKER_COMPOSE_FILE"
    exit 1
fi

log_success "Pre-flight checks passed"

###############################################################################
# Clean Previous Test Data
###############################################################################

log_info "Cleaning up previous test infrastructure..."

# Stop and remove existing containers
docker compose -f "$DOCKER_COMPOSE_FILE" down -v 2>/dev/null || true

# Clean up test data directories (optional - uncomment if needed)
# rm -rf "$PROJECT_ROOT/test_data/postgres" 2>/dev/null || true
# rm -rf "$PROJECT_ROOT/test_data/redis" 2>/dev/null || true

log_success "Cleanup completed"

###############################################################################
# Start Test Infrastructure
###############################################################################

log_info "Starting test infrastructure services..."

# Pull latest images
log_info "Pulling latest Docker images..."
docker compose -f "$DOCKER_COMPOSE_FILE" pull

# Start services
log_info "Starting services (PostgreSQL, Redis, Prometheus, Grafana)..."
docker compose -f "$DOCKER_COMPOSE_FILE" up -d

log_success "Services started"

###############################################################################
# Wait for Services to be Healthy
###############################################################################

log_info "Waiting for services to become healthy..."

wait_for_service() {
    local service_name=$1
    local container_name=$2
    local timeout=$HEALTH_CHECK_TIMEOUT
    local elapsed=0

    log_info "Checking health of $service_name..."

    while [ $elapsed -lt $timeout ]; do
        # Check if container is running
        if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            log_warning "$service_name container not running yet..."
            sleep $HEALTH_CHECK_INTERVAL
            elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
            continue
        fi

        # Check health status
        health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "none")

        if [ "$health_status" = "healthy" ]; then
            log_success "$service_name is healthy"
            return 0
        elif [ "$health_status" = "none" ]; then
            # Service has no health check, just verify it's running
            if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
                log_success "$service_name is running (no health check)"
                return 0
            fi
        fi

        log_info "$service_name health status: $health_status (waiting...)"
        sleep $HEALTH_CHECK_INTERVAL
        elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
    done

    log_error "$service_name failed to become healthy within ${timeout}s"
    return 1
}

# Wait for each service
wait_for_service "PostgreSQL" "saas-postgres-test" || exit 1
wait_for_service "Redis" "saas-redis-test" || exit 1
wait_for_service "Prometheus" "saas-prometheus-test" || exit 1
wait_for_service "Grafana" "saas-grafana-test" || exit 1

# Note: SaaS API is commented out in compose file by default
if docker ps --format '{{.Names}}' | grep -q "saas-api-test"; then
    wait_for_service "SaaS API" "saas-api-test" || exit 1
fi

log_success "All services are healthy"

###############################################################################
# Verify Service Connectivity
###############################################################################

log_info "Verifying service connectivity..."

# Test PostgreSQL connection
log_info "Testing PostgreSQL connection..."
if docker exec saas-postgres-test psql -U postgres -d test_saas -c "SELECT version();" > /dev/null 2>&1; then
    log_success "PostgreSQL connection verified"
else
    log_error "Failed to connect to PostgreSQL"
    exit 1
fi

# Test Redis connection
log_info "Testing Redis connection..."
if docker exec saas-redis-test redis-cli -a test_redis_password ping | grep -q "PONG"; then
    log_success "Redis connection verified"
else
    log_error "Failed to connect to Redis"
    exit 1
fi

# Test Prometheus
log_info "Testing Prometheus..."
if curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
    log_success "Prometheus is accessible"
else
    log_warning "Prometheus may not be fully ready yet"
fi

# Test Grafana
log_info "Testing Grafana..."
if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
    log_success "Grafana is accessible"
else
    log_warning "Grafana may not be fully ready yet"
fi

###############################################################################
# Display Service Information
###############################################################################

echo ""
echo "=================================================="
log_success "Test Infrastructure Setup Complete!"
echo "=================================================="
echo ""
echo "Service Information:"
echo "-------------------"
echo "PostgreSQL:"
echo "  - Host: localhost"
echo "  - Port: 5433"
echo "  - Database: test_saas"
echo "  - User: postgres"
echo "  - Password: postgres"
echo "  - Connection String: postgresql://postgres:postgres@localhost:5433/test_saas"
echo ""
echo "Redis:"
echo "  - Host: localhost"
echo "  - Port: 6380"
echo "  - Password: test_redis_password"
echo "  - Connection String: redis://:test_redis_password@localhost:6380"
echo ""
echo "Prometheus:"
echo "  - URL: http://localhost:9090"
echo "  - Metrics endpoint: http://localhost:9090/metrics"
echo ""
echo "Grafana:"
echo "  - URL: http://localhost:3000"
echo "  - Username: admin"
echo "  - Password: admin"
echo ""
echo "Environment Variables (for testing):"
echo "  export TEST_DATABASE_URL='postgresql://postgres:postgres@localhost:5433/test_saas'"
echo "  export TEST_REDIS_HOST='localhost'"
echo "  export TEST_REDIS_PORT='6380'"
echo "  export TEST_REDIS_PASSWORD='test_redis_password'"
echo ""
echo "To view logs: docker compose -f $DOCKER_COMPOSE_FILE logs -f"
echo "To stop services: $SCRIPT_DIR/teardown-test-infrastructure.sh"
echo "=================================================="
