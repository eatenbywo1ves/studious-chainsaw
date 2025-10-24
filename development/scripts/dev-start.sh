#!/bin/bash
# Quick Development Environment Startup Script
# Usage: ./scripts/dev-start.sh [project]

set -e

PROJECT="${1:-all}"
DEV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "🚀 Starting Development Environment..."
echo "📂 Root: $DEV_ROOT"
echo ""

start_saas() {
    echo "🔹 Starting SaaS API..."
    cd "$DEV_ROOT/saas"

    # Activate virtual environment
    if [ -d "venv" ]; then
        source venv/bin/activate
    else
        echo "⚠️  No virtual environment found. Creating one..."
        python -m venv venv
        source venv/bin/activate
        pip install -r requirements-saas.txt
    fi

    # Check .env file
    if [ ! -f ".env" ]; then
        echo "⚠️  No .env file found. Copying from example..."
        cp ../.env.example .env
    fi

    # Start server in background
    echo "✓ Starting SaaS API on port 8000..."
    uvicorn app.main:app --reload --port 8000 &
    SAAS_PID=$!
    echo "  PID: $SAAS_PID"
    echo ""
}

start_mlsec() {
    echo "🔹 Starting ML SecTest Framework..."
    cd "$DEV_ROOT/ml-sectest-framework"

    # Activate virtual environment
    if [ -d "venv" ]; then
        source venv/bin/activate
    else
        echo "⚠️  No virtual environment found. Creating one..."
        python -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
    fi

    # Start server in background
    echo "✓ Starting ML SecTest API on port 8081..."
    uvicorn app.main:app --reload --port 8081 &
    MLSEC_PID=$!
    echo "  PID: $MLSEC_PID"
    echo ""
}

start_redis() {
    echo "🔹 Starting Redis..."
    if command -v redis-server &> /dev/null; then
        redis-server --daemonize yes
        echo "✓ Redis started"
    else
        echo "⚠️  Redis not installed. Using Docker..."
        docker run -d --name redis-dev -p 6379:6379 redis:alpine
    fi
    echo ""
}

stop_all() {
    echo "🛑 Stopping all services..."

    # Stop background processes
    pkill -f "uvicorn" || true
    pkill -f "redis-server" || true
    docker stop redis-dev 2>/dev/null || true
    docker rm redis-dev 2>/dev/null || true

    echo "✓ All services stopped"
}

# Parse command
case "$PROJECT" in
    saas)
        start_saas
        ;;
    mlsec)
        start_mlsec
        ;;
    redis)
        start_redis
        ;;
    all)
        start_redis
        start_saas
        start_mlsec
        ;;
    stop)
        stop_all
        exit 0
        ;;
    *)
        echo "Usage: $0 [saas|mlsec|redis|all|stop]"
        exit 1
        ;;
esac

# Display status
echo "════════════════════════════════════════"
echo "✅ Development Environment Ready!"
echo ""
echo "📍 API Endpoints:"
[ "$PROJECT" = "all" ] || [ "$PROJECT" = "saas" ] && echo "   • SaaS API:     http://localhost:8000"
[ "$PROJECT" = "all" ] || [ "$PROJECT" = "saas" ] && echo "   • SaaS Docs:    http://localhost:8000/docs"
[ "$PROJECT" = "all" ] || [ "$PROJECT" = "mlsec" ] && echo "   • ML SecTest:   http://localhost:8081"
[ "$PROJECT" = "all" ] || [ "$PROJECT" = "mlsec" ] && echo "   • SecTest Docs: http://localhost:8081/docs"
[ "$PROJECT" = "all" ] || [ "$PROJECT" = "redis" ] && echo "   • Redis:        localhost:6379"
echo ""
echo "🛠️  Quick Commands:"
echo "   • Stop all:     $0 stop"
echo "   • View logs:    tail -f logs/*.log"
echo "   • Run tests:    pytest tests/"
echo ""
echo "Press Ctrl+C to stop watching logs..."
echo "════════════════════════════════════════"

# Keep script running if servers were started
if [ "$PROJECT" != "redis" ]; then
    wait
fi
