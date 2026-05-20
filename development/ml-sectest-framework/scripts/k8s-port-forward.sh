#!/usr/bin/env bash
# ML-SecTest Kubernetes Port-Forward Management Script
# Usage: ./k8s-port-forward.sh [start|stop|status|restart]

set -e

# Configuration
ML_SECTEST_LOCAL_PORT=8085
ML_SECTEST_REMOTE_PORT=80
PROMETHEUS_LOCAL_PORT=9092  # Changed from 9091 to avoid conflicts
PROMETHEUS_REMOTE_PORT=9090

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a port is in use
check_port() {
    local port=$1
    if netstat -ano | grep -q ":${port}"; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to find PID using a specific port
get_pid_on_port() {
    local port=$1
    # Extract PID from netstat output
    local pid=$(netstat -ano | grep ":${port}" | grep "LISTENING" | awk '{print $NF}' | head -1)
    echo "$pid"
}

# Function to kill all kubectl port-forward processes
kill_all_port_forwards() {
    echo -e "${YELLOW}Stopping all kubectl port-forward processes...${NC}"

    # Find all kubectl processes
    local pids=$(tasklist | grep "kubectl.exe" | awk '{print $2}' || echo "")

    if [ -z "$pids" ]; then
        echo -e "${GREEN}No kubectl port-forward processes found.${NC}"
        return 0
    fi

    # Kill each process
    for pid in $pids; do
        echo "  Killing kubectl process PID: $pid"
        taskkill //F //PID "$pid" 2>/dev/null || echo "    Failed to kill PID $pid"
    done

    sleep 2
    echo -e "${GREEN}All kubectl processes terminated.${NC}"
}

# Function to start port-forwards
start_port_forwards() {
    echo -e "${YELLOW}Starting ML-SecTest port-forwards...${NC}"

    # Check if ports are available
    if check_port "$ML_SECTEST_LOCAL_PORT"; then
        local pid=$(get_pid_on_port "$ML_SECTEST_LOCAL_PORT")
        echo -e "${RED}Error: Port $ML_SECTEST_LOCAL_PORT is already in use by PID $pid${NC}"
        echo "Run: ./k8s-port-forward.sh stop (to clean up)"
        exit 1
    fi

    if check_port "$PROMETHEUS_LOCAL_PORT"; then
        local pid=$(get_pid_on_port "$PROMETHEUS_LOCAL_PORT")
        echo -e "${RED}Error: Port $PROMETHEUS_LOCAL_PORT is already in use by PID $pid${NC}"
        echo "Run: ./k8s-port-forward.sh stop (to clean up)"
        exit 1
    fi

    # Start ML-SecTest API port-forward
    echo "  Starting ML-SecTest API: localhost:${ML_SECTEST_LOCAL_PORT} -> ml-sectest-api:${ML_SECTEST_REMOTE_PORT}"
    kubectl port-forward -n ml-sectest svc/ml-sectest-api "${ML_SECTEST_LOCAL_PORT}:${ML_SECTEST_REMOTE_PORT}" > /dev/null 2>&1 &
    local ml_pid=$!
    echo "    PID: $ml_pid"

    # Start Prometheus port-forward
    echo "  Starting Prometheus: localhost:${PROMETHEUS_LOCAL_PORT} -> prometheus:${PROMETHEUS_REMOTE_PORT}"
    kubectl port-forward -n monitoring svc/prometheus "${PROMETHEUS_LOCAL_PORT}:${PROMETHEUS_REMOTE_PORT}" > /dev/null 2>&1 &
    local prom_pid=$!
    echo "    PID: $prom_pid"

    # Wait a moment for port-forwards to establish
    sleep 3

    # Verify connections
    echo -e "${YELLOW}Verifying connections...${NC}"

    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${ML_SECTEST_LOCAL_PORT}/health" | grep -q "200"; then
        echo -e "  ${GREEN}✓${NC} ML-SecTest API: http://localhost:${ML_SECTEST_LOCAL_PORT}/health"
    else
        echo -e "  ${RED}✗${NC} ML-SecTest API: Failed to connect"
    fi

    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PROMETHEUS_LOCAL_PORT}/-/healthy" | grep -q "200"; then
        echo -e "  ${GREEN}✓${NC} Prometheus: http://localhost:${PROMETHEUS_LOCAL_PORT}"
    else
        echo -e "  ${YELLOW}⚠${NC} Prometheus: May still be starting..."
    fi

    echo ""
    echo -e "${GREEN}Port-forwards started successfully!${NC}"
    echo ""
    echo "Access points:"
    echo "  ML-SecTest API:  http://localhost:${ML_SECTEST_LOCAL_PORT}"
    echo "  API Health:      http://localhost:${ML_SECTEST_LOCAL_PORT}/health"
    echo "  API Docs:        http://localhost:${ML_SECTEST_LOCAL_PORT}/docs"
    echo "  Prometheus:      http://localhost:${PROMETHEUS_LOCAL_PORT}"
    echo ""
    echo "To stop: ./k8s-port-forward.sh stop"
}

# Function to show status
show_status() {
    echo -e "${YELLOW}Kubernetes Port-Forward Status:${NC}"
    echo ""

    # Check ML-SecTest API
    if check_port "$ML_SECTEST_LOCAL_PORT"; then
        local pid=$(get_pid_on_port "$ML_SECTEST_LOCAL_PORT")
        echo -e "  ${GREEN}✓${NC} ML-SecTest API: localhost:${ML_SECTEST_LOCAL_PORT} (PID: $pid)"

        # Test health endpoint
        if curl -s "http://localhost:${ML_SECTEST_LOCAL_PORT}/health" > /dev/null 2>&1; then
            echo -e "    ${GREEN}Health check: PASSED${NC}"
        else
            echo -e "    ${RED}Health check: FAILED${NC}"
        fi
    else
        echo -e "  ${RED}✗${NC} ML-SecTest API: Not running"
    fi

    # Check Prometheus
    if check_port "$PROMETHEUS_LOCAL_PORT"; then
        local pid=$(get_pid_on_port "$PROMETHEUS_LOCAL_PORT")
        echo -e "  ${GREEN}✓${NC} Prometheus: localhost:${PROMETHEUS_LOCAL_PORT} (PID: $pid)"
    else
        echo -e "  ${RED}✗${NC} Prometheus: Not running"
    fi

    echo ""

    # Show all kubectl processes
    local kubectl_procs=$(tasklist | grep "kubectl.exe" || echo "")
    if [ -n "$kubectl_procs" ]; then
        echo "Active kubectl processes:"
        echo "$kubectl_procs"
    fi
}

# Main script logic
case "${1:-start}" in
    start)
        start_port_forwards
        ;;
    stop)
        kill_all_port_forwards
        ;;
    status)
        show_status
        ;;
    restart)
        echo -e "${YELLOW}Restarting port-forwards...${NC}"
        kill_all_port_forwards
        sleep 2
        start_port_forwards
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        echo ""
        echo "Commands:"
        echo "  start   - Start port-forward connections"
        echo "  stop    - Stop all kubectl port-forward processes"
        echo "  status  - Show current port-forward status"
        echo "  restart - Stop and restart port-forwards"
        exit 1
        ;;
esac
