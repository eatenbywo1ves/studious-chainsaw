#!/bin/bash
# Deploy go-deployment-demo to Railway.app
# Railway supports Docker deployments without CLI installation

set -e

# Configuration
PROJECT_NAME="go-deployment-demo"
DOCKER_USERNAME="${DOCKER_USERNAME:-your-dockerhub-username}"
IMAGE="${DOCKER_USERNAME}/${PROJECT_NAME}:latest"

echo "=========================================="
echo "Railway.app Deployment Script"
echo "=========================================="
echo "Project: $PROJECT_NAME"
echo "Image: $IMAGE"
echo "=========================================="

# Check if Railway CLI is installed
if command -v railway &> /dev/null; then
    echo "✓ Railway CLI found"
    
    # Login (if not already)
    echo "Step 1: Checking Railway authentication..."
    if ! railway whoami &> /dev/null; then
        echo "Logging in to Railway..."
        railway login
    fi
    
    # Initialize project (if needed)
    echo "Step 2: Initializing Railway project..."
    if [ ! -f "railway.json" ]; then
        railway init
    fi
    
    # Deploy
    echo "Step 3: Deploying to Railway..."
    railway up --service ${PROJECT_NAME}
    
    # Get URL
    echo "Step 4: Retrieving service URL..."
    SERVICE_URL=$(railway status --json | grep -o '"url":"[^"]*' | cut -d'"' -f4)
    
    echo "=========================================="
    echo "✅ Deployment Complete!"
    echo "=========================================="
    echo "Service URL: $SERVICE_URL"
    echo "Dashboard: https://railway.app/dashboard"
    echo "=========================================="
    
else
    echo "⚠️  Railway CLI not installed"
    echo ""
    echo "=========================================="
    echo "Web-Based Deployment Instructions"
    echo "=========================================="
    echo ""
    echo "1. Visit: https://railway.app"
    echo "2. Click 'Start a New Project'"
    echo "3. Select 'Deploy from Docker Hub'"
    echo "4. Enter image: $IMAGE"
    echo "5. Configure:"
    echo "   - Port: 8080"
    echo "   - Environment Variables:"
    echo "     PORT=8080"
    echo "     ENVIRONMENT=production"
    echo "     VERSION=1.0.0"
    echo "6. Click 'Deploy'"
    echo ""
    echo "Railway will automatically:"
    echo "- Pull the Docker image"
    echo "- Deploy to global edge network"
    echo "- Provide HTTPS URL"
    echo "- Auto-scale based on traffic"
    echo ""
    echo "=========================================="
    echo "CLI Installation (Optional):"
    echo "=========================================="
    echo "npm install -g @railway/cli"
    echo "railway login"
    echo "./deploy-to-railway.sh"
    echo "=========================================="
fi
