#!/bin/bash
# Deploy go-deployment-demo to Fly.io
# Fly.io CLI can be installed via npm (already available)

set -e

# Configuration
APP_NAME="go-deployment-demo"
REGION="${FLY_REGION:-ord}"  # Chicago by default

echo "=========================================="
echo "Fly.io Deployment Script"
echo "=========================================="
echo "App: $APP_NAME"
echo "Region: $REGION"
echo "=========================================="

# Check if flyctl is installed
if command -v flyctl &> /dev/null || command -v fly &> /dev/null; then
    FLYCTL_CMD=$(command -v flyctl || command -v fly)
    echo "✓ Fly CLI found: $FLYCTL_CMD"
    
    # Step 1: Login (if not already)
    echo "Step 1: Checking Fly.io authentication..."
    if ! $FLYCTL_CMD auth whoami &> /dev/null; then
        echo "Logging in to Fly.io..."
        $FLYCTL_CMD auth login
    fi
    echo "✓ Authenticated"
    
    # Step 2: Create app (if needed)
    echo "Step 2: Creating/verifying app..."
    if ! $FLYCTL_CMD apps list | grep -q "$APP_NAME"; then
        echo "Creating new app..."
        $FLYCTL_CMD apps create $APP_NAME --org personal
    fi
    echo "✓ App ready"
    
    # Step 3: Deploy
    echo "Step 3: Deploying to Fly.io..."
    $FLYCTL_CMD deploy --config fly.toml --local-only
    
    # Step 4: Get URL
    echo "Step 4: Retrieving app URL..."
    APP_URL=$($FLYCTL_CMD status --app $APP_NAME --json | grep -o '"hostname":"[^"]*' | cut -d'"' -f4)
    
    echo "=========================================="
    echo "✅ Deployment Complete!"
    echo "=========================================="
    echo "App URL: https://$APP_URL"
    echo "Dashboard: https://fly.io/apps/$APP_NAME"
    echo ""
    echo "Test endpoints:"
    echo "  curl https://$APP_URL/health"
    echo "  curl https://$APP_URL/ready"
    echo "  curl https://$APP_URL/metrics"
    echo "=========================================="
    
else
    echo "⚠️  Fly CLI not installed"
    echo ""
    echo "=========================================="
    echo "Installation Options:"
    echo "=========================================="
    echo ""
    echo "Option 1: Install via npm (recommended - npm already available)"
    echo "  npm install -g @flyctl/flyctl"
    echo ""
    echo "Option 2: Install via PowerShell"
    echo "  powershell -Command \"iwr https://fly.io/install.ps1 -useb | iex\""
    echo ""
    echo "Option 3: Install via Homebrew (if available)"
    echo "  brew install flyctl"
    echo ""
    echo "=========================================="
    echo "After Installation:"
    echo "=========================================="
    echo "  flyctl auth login"
    echo "  ./deploy-to-fly.sh"
    echo ""
    echo "=========================================="
    echo "Fly.io Features:"
    echo "=========================================="
    echo "✓ Global edge network (30+ regions)"
    echo "✓ Automatic HTTPS"
    echo "✓ Instant deploys (<1 minute)"
    echo "✓ Free allowance: 3 VMs, 256MB RAM each"
    echo "✓ Built-in load balancing"
    echo "✓ Health checks and auto-restart"
    echo "=========================================="
fi
