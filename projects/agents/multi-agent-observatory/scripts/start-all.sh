#!/bin/bash
# Start all components of the Multi-Agent Observatory System

echo "🚀 Starting Multi-Agent Observatory System..."

# Function to cleanup on exit
cleanup() {
    echo "🛑 Shutting down all components..."
    jobs -p | xargs -r kill
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start server in background
echo "🖥️  Starting Observatory Server..."
cd server
bun run start &
SERVER_PID=$!
cd ..

# Wait for server to start
sleep 3

# Start all agents
echo "🤖 Starting agents..."
export OBSERVATORY_SERVER="ws://localhost:${PORT:-8090}/ws"
for agent in agents/agent-*; do
    if [ -d "$agent" ] && [ -f "$agent/package.json" ]; then
        echo "  Starting $(basename $agent)..."
        cd "$agent"
        npm start &
        cd ../../
    fi
done

# Start dashboard
echo "📊 Starting dashboard..."
cd dashboard
python -m http.server 3000 &
DASHBOARD_PID=$!
cd ..

echo "✅ All components started successfully!"
echo ""
echo "🌐 Access points:"
echo "  📊 Dashboard:    http://localhost:3000"
echo "  🔌 API:          http://localhost:${PORT:-8090}"
echo "  ❤️  Health check: http://localhost:${PORT:-8090}/health"
echo "  🔍 WebSocket:    ws://localhost:${PORT:-8090}/ws"
echo ""
echo "Press Ctrl+C to stop all components"

# Wait for background processes
wait