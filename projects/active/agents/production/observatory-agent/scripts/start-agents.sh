#!/bin/bash
# Start all agents

echo "🤖 Starting all Observatory Agents..."

# Function to cleanup on exit
cleanup() {
    echo "🛑 Stopping all agents..."
    jobs -p | xargs -r kill
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start all agents in background
for agent in agents/agent-*; do
    if [ -d "$agent" ] && [ -f "$agent/package.json" ]; then
        agent_name=$(basename "$agent")
        echo "  🚀 Starting $agent_name..."
        cd "$agent"
        npm start &
        cd ../../
        sleep 1
    fi
done

echo "✅ All agents started!"
echo "Press Ctrl+C to stop all agents"

# Wait for background processes
wait