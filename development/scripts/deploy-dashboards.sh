#!/bin/bash
# Grafana Dashboard Deployment Script for Linux/macOS
# Catalytic Computing Platform

set -e

echo "========================================"
echo "Catalytic Computing - Grafana Dashboard Deployment"
echo "========================================"

# Set default values
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
DASHBOARDS_DIR="${DASHBOARDS_DIR:-monitoring/grafana/dashboards}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if API key is provided
if [ -z "$GRAFANA_API_KEY" ]; then
    echo "❌ Error: GRAFANA_API_KEY environment variable is not set"
    echo "Please set it using: export GRAFANA_API_KEY=your_api_key_here"
    exit 1
fi

echo "Using Grafana URL: $GRAFANA_URL"
echo "Using Dashboards Directory: $DASHBOARDS_DIR"
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed or not in PATH"
    exit 1
fi

# Install required Python packages
echo "📦 Installing required Python packages..."
pip3 install requests pathlib 2>/dev/null || {
    echo "⚠️  Warning: Could not install packages. Continuing anyway..."
}

# Run the deployment script
echo
echo "🚀 Starting dashboard deployment..."
python3 "$SCRIPT_DIR/deploy-grafana-dashboards.py" \
    --grafana-url "$GRAFANA_URL" \
    --api-key "$GRAFANA_API_KEY" \
    --dashboards-dir "$DASHBOARDS_DIR"

echo
echo "✅ Dashboard deployment completed successfully!"
echo
echo "You can now access your dashboards at:"
echo "$GRAFANA_URL/dashboards"
echo