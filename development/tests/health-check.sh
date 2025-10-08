#!/bin/bash

###############################################################################
# Test Infrastructure Health Check Script
# Purpose: Verify all test services are healthy and accessible
# Author: BMAD DevOps Agent
# Date: 2025-10-06
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$SCRIPT_DIR/integration"
DOCKER_COMPOSE_FILE="$INTEGRATION_DIR/docker-compose.test.yml"

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Track service status
declare -A SERVICE_STATUS

###############################################################################
# Health Check Functions
###############################################################################

check_docker_running() {
    log_test "Checking Docker daemon..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if docker info > /dev/null 2>&1; then
        log_success "Docker daemon is running"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_error "Docker daemon is not running"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_container_running() {
    local container_name=$1
    log_test "Checking if $container_name is running..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        log_success "$container_name is running"
        SERVICE_STATUS[$container_name]="running"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_error "$container_name is not running"
        SERVICE_STATUS[$container_name]="stopped"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_container_health() {
    local container_name=$1
    log_test "Checking health of $container_name..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    local health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "none")

    if [ "$health_status" = "healthy" ]; then
        log_success "$container_name is healthy"
        SERVICE_STATUS["${container_name}_health"]="healthy"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    elif [ "$health_status" = "none" ]; then
        log_warning "$container_name has no health check configured"
        SERVICE_STATUS["${container_name}_health"]="no_healthcheck"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_error "$container_name health status: $health_status"
        SERVICE_STATUS["${container_name}_health"]=$health_status
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_postgres() {
    log_test "Testing PostgreSQL connectivity..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if docker exec saas-postgres-test psql -U postgres -d test_saas -c "SELECT 1;" > /dev/null 2>&1; then
        log_success "PostgreSQL is accepting connections"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))

        # Get version
        local pg_version=$(docker exec saas-postgres-test psql -U postgres -d test_saas -t -c "SELECT version();" 2>/dev/null | head -n1)
        echo "  → Version: ${pg_version}"
        return 0
    else
        log_error "PostgreSQL is not accepting connections"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_redis() {
    log_test "Testing Redis connectivity..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if docker exec saas-redis-test redis-cli -a test_redis_password ping 2>/dev/null | grep -q "PONG"; then
        log_success "Redis is accepting connections"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))

        # Get info
        local redis_version=$(docker exec saas-redis-test redis-cli -a test_redis_password INFO server 2>/dev/null | grep "redis_version" | cut -d: -f2 | tr -d '\r')
        local used_memory=$(docker exec saas-redis-test redis-cli -a test_redis_password INFO memory 2>/dev/null | grep "used_memory_human" | cut -d: -f2 | tr -d '\r')
        echo "  → Version: ${redis_version}"
        echo "  → Memory: ${used_memory}"
        return 0
    else
        log_error "Redis is not accepting connections"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_prometheus() {
    log_test "Testing Prometheus accessibility..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
        log_success "Prometheus is accessible"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))

        # Get targets
        local targets_up=$(curl -s http://localhost:9090/api/v1/targets 2>/dev/null | grep -o '"health":"up"' | wc -l)
        echo "  → Active targets: ${targets_up}"
        return 0
    else
        log_error "Prometheus is not accessible"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_grafana() {
    log_test "Testing Grafana accessibility..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
        log_success "Grafana is accessible"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))

        # Try to get version
        local grafana_info=$(curl -s http://localhost:3000/api/health 2>/dev/null)
        echo "  → Status: ${grafana_info}"
        return 0
    else
        log_error "Grafana is not accessible"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_port_listening() {
    local port=$1
    local service=$2
    log_test "Checking if port $port is listening ($service)..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if command -v netstat &> /dev/null; then
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            log_success "Port $port is listening ($service)"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            return 0
        fi
    elif command -v ss &> /dev/null; then
        if ss -tuln 2>/dev/null | grep -q ":$port "; then
            log_success "Port $port is listening ($service)"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            return 0
        fi
    fi

    # Fallback: try to connect
    if timeout 1 bash -c "cat < /dev/null > /dev/tcp/localhost/$port" 2>/dev/null; then
        log_success "Port $port is listening ($service)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_error "Port $port is not listening ($service)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_network() {
    log_test "Checking Docker network..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if docker network ls | grep -q "integration_test-network"; then
        log_success "Test network exists"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_error "Test network does not exist"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_volumes() {
    log_test "Checking Docker volumes..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    local expected_volumes=("integration_postgres-test-data" "integration_redis-test-data" "integration_prometheus-test-data" "integration_grafana-test-data")
    local volumes_ok=true

    for vol in "${expected_volumes[@]}"; do
        if docker volume ls | grep -q "$vol"; then
            echo "  → Found: $vol"
        else
            log_warning "Volume not found: $vol"
            volumes_ok=false
        fi
    done

    if [ "$volumes_ok" = true ]; then
        log_success "All expected volumes exist"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        log_warning "Some volumes are missing (will be created on first run)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    fi
}

###############################################################################
# Main Health Check
###############################################################################

echo "=================================================="
echo "  Test Infrastructure Health Check"
echo "=================================================="
echo ""

# 1. Check Docker
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Docker Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_docker_running
echo ""

# 2. Check containers
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Container Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_container_running "saas-postgres-test"
check_container_health "saas-postgres-test"
echo ""

check_container_running "saas-redis-test"
check_container_health "saas-redis-test"
echo ""

check_container_running "saas-prometheus-test"
check_container_health "saas-prometheus-test"
echo ""

check_container_running "saas-grafana-test"
check_container_health "saas-grafana-test"
echo ""

# 3. Check connectivity
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Service Connectivity"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_postgres
echo ""

check_redis
echo ""

check_prometheus
echo ""

check_grafana
echo ""

# 4. Check ports
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Port Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_port_listening 5433 "PostgreSQL"
check_port_listening 6380 "Redis"
check_port_listening 9090 "Prometheus"
check_port_listening 3000 "Grafana"
echo ""

# 5. Check network and volumes
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Infrastructure"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_network
echo ""

check_volumes
echo ""

# Summary
echo "=================================================="
echo "  Health Check Summary"
echo "=================================================="
echo ""
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo ""

if [ $FAILED_CHECKS -eq 0 ]; then
    log_success "All health checks passed!"
    echo ""
    echo "Test infrastructure is ready for integration tests."
    echo ""
    echo "Connection Strings:"
    echo "  PostgreSQL: postgresql://postgres:postgres@localhost:5433/test_saas"
    echo "  Redis: redis://:test_redis_password@localhost:6380"
    echo "  Prometheus: http://localhost:9090"
    echo "  Grafana: http://localhost:3000 (admin/admin)"
    echo ""
    exit 0
else
    log_error "Some health checks failed!"
    echo ""
    echo "To view logs: docker compose -f $DOCKER_COMPOSE_FILE logs"
    echo "To restart: $SCRIPT_DIR/setup-test-infrastructure.sh"
    echo ""
    exit 1
fi
