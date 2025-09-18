#!/bin/bash
# Start all MCP services with orchestrator
# Unix/Linux/WSL script for launching MCP server infrastructure

echo "========================================"
echo "     MCP Services Startup Script"
echo "========================================"
echo

cd /c/Users/Corbin || cd ~/

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    exit 1
fi

# Check for required packages
echo "Checking dependencies..."
pip3 show psutil &> /dev/null || pip3 install psutil
pip3 show flask &> /dev/null || pip3 install flask flask-cors

echo
echo "Starting MCP Orchestrator..."
echo "========================================"

# Function to cleanup on exit
cleanup() {
    echo
    echo "Shutting down services..."
    python3 Tools/mcp-orchestrator/mcp_orchestrator.py stop
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start orchestrator in background
python3 Tools/mcp-orchestrator/mcp_orchestrator.py monitor &
ORCHESTRATOR_PID=$!

echo
echo "Waiting for orchestrator to initialize..."
sleep 5

# Ask about dashboard
echo
read -p "Start web dashboard? (y/n): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting Dashboard at http://localhost:5000"
    python3 Tools/mcp-orchestrator/dashboard.py &
    DASHBOARD_PID=$!
    sleep 3

    # Try to open browser
    if command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:5000
    elif command -v open &> /dev/null; then
        open http://localhost:5000
    fi
fi

echo
echo "========================================"
echo "All services started successfully!"
echo
echo "Orchestrator PID: $ORCHESTRATOR_PID"
[[ ! -z $DASHBOARD_PID ]] && echo "Dashboard PID: $DASHBOARD_PID (http://localhost:5000)"
echo
echo "Press Ctrl+C to stop all services"
echo "========================================"

# Show status
python3 Tools/mcp-orchestrator/mcp_orchestrator.py status

# Wait for interrupt
wait