#!/bin/bash
# Multi-Agent Observatory Setup Script

echo "🚀 Setting up Multi-Agent Observatory System..."

# Check if bun is installed
if ! command -v bun &> /dev/null; then
    echo "❌ Bun is required but not installed. Please install Bun first:"
    echo "   curl -fsSL https://bun.sh/install | bash"
    exit 1
fi

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed. Please install Node.js first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Install server dependencies
echo "📦 Installing server dependencies..."
cd server
bun install
cd ..

# Install agent dependencies
echo "📦 Installing agent dependencies..."
for agent in agents/agent-*; do
    if [ -d "$agent" ]; then
        echo "  Installing dependencies for $agent..."
        cd "$agent"
        npm install
        cd ../../
    fi
done

# Initialize database
echo "🗄️ Initializing database..."
cd server
bun run init-db
cd ..

echo "✅ Setup completed successfully!"
echo ""
echo "🎯 Quick start commands:"
echo "  Start server:     cd server && bun run start"
echo "  Start all agents: ./scripts/start-agents.sh"
echo "  Start dashboard:  cd dashboard && npm run dev"
echo "  Start everything: ./scripts/start-all.sh"
echo ""
echo "🌐 Access points:"
echo "  Dashboard:    http://localhost:3000"
echo "  API:          http://localhost:8080"
echo "  Health check: http://localhost:8080/health"