#!/bin/bash

###############################################################################
# Test Infrastructure Teardown Script
# Purpose: Clean shutdown and cleanup of test environment
# Author: BMAD DevOps Agent
# Date: 2025-10-06
###############################################################################

set -e  # Exit on error

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
INTEGRATION_DIR="$PROJECT_ROOT/tests/integration"
DOCKER_COMPOSE_FILE="$INTEGRATION_DIR/docker-compose.test.yml"

# Parse arguments
REMOVE_VOLUMES=false
REMOVE_DATA=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--volumes)
            REMOVE_VOLUMES=true
            shift
            ;;
        -d|--data)
            REMOVE_DATA=true
            shift
            ;;
        -a|--all)
            REMOVE_VOLUMES=true
            REMOVE_DATA=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --volumes    Remove Docker volumes"
            echo "  -d, --data       Remove local test data directories"
            echo "  -a, --all        Remove both volumes and data"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                # Stop containers only"
            echo "  $0 -v             # Stop containers and remove volumes"
            echo "  $0 -a             # Complete cleanup (containers, volumes, data)"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

###############################################################################
# Main Teardown Process
###############################################################################

log_info "Starting test infrastructure teardown..."
echo "=================================================="

# Check if docker-compose.test.yml exists
if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
    log_error "docker-compose.test.yml not found at: $DOCKER_COMPOSE_FILE"
    exit 1
fi

# Stop and remove containers
log_info "Stopping test infrastructure services..."

if [ "$REMOVE_VOLUMES" = true ]; then
    log_warning "Removing containers AND volumes..."
    docker compose -f "$DOCKER_COMPOSE_FILE" down -v
    log_success "Containers and volumes removed"
else
    log_info "Removing containers only (volumes preserved)..."
    docker compose -f "$DOCKER_COMPOSE_FILE" down
    log_success "Containers removed (volumes preserved)"
fi

# Remove local test data directories if requested
if [ "$REMOVE_DATA" = true ]; then
    log_info "Removing local test data directories..."

    if [ -d "$PROJECT_ROOT/test_data/postgres" ]; then
        rm -rf "$PROJECT_ROOT/test_data/postgres"
        log_success "Removed PostgreSQL test data"
    fi

    if [ -d "$PROJECT_ROOT/test_data/redis" ]; then
        rm -rf "$PROJECT_ROOT/test_data/redis"
        log_success "Removed Redis test data"
    fi

    if [ -d "$PROJECT_ROOT/test_data" ]; then
        # Remove parent directory if empty
        rmdir "$PROJECT_ROOT/test_data" 2>/dev/null || true
    fi
fi

# Display remaining Docker resources
echo ""
log_info "Checking for remaining test containers..."
test_containers=$(docker ps -a --filter "name=saas-*-test" --format "{{.Names}}" || true)

if [ -z "$test_containers" ]; then
    log_success "No test containers remaining"
else
    log_warning "Remaining test containers:"
    echo "$test_containers"
fi

# Check for remaining volumes
if [ "$REMOVE_VOLUMES" = false ]; then
    echo ""
    log_info "Test volumes are preserved. To remove them, run:"
    echo "  $0 --volumes"
    echo ""
    log_info "Preserved volumes:"
    docker volume ls --filter "name=integration_" --format "  - {{.Name}}" || true
fi

# Summary
echo ""
echo "=================================================="
log_success "Test Infrastructure Teardown Complete!"
echo "=================================================="

if [ "$REMOVE_VOLUMES" = false ]; then
    echo ""
    log_info "Test data preserved for next run"
    log_info "For complete cleanup, run: $0 --all"
fi

echo ""
log_info "To restart infrastructure: $SCRIPT_DIR/setup-test-infrastructure.sh"
echo "=================================================="
