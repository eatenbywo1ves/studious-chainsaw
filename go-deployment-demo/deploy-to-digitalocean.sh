#!/bin/bash
# Deploy go-deployment-demo to DigitalOcean App Platform
# Supports both CLI and web-based deployment

set -e

# Configuration
APP_NAME="go-deployment-demo"
REGION="${DO_REGION:-nyc}"
DOCKER_USERNAME="${DOCKER_USERNAME:-your-dockerhub-username}"
IMAGE="${DOCKER_USERNAME}/${APP_NAME}:latest"

echo "=========================================="
echo "DigitalOcean App Platform Deployment"
echo "=========================================="
echo "App: $APP_NAME"
echo "Region: $REGION"
echo "Image: $IMAGE"
echo "=========================================="

# Check if doctl is installed
if command -v doctl &> /dev/null; then
    echo "✓ DigitalOcean CLI found"
    
    # Step 1: Authenticate
    echo "Step 1: Checking DigitalOcean authentication..."
    if ! doctl auth list &> /dev/null; then
        echo "Please authenticate:"
        echo "  doctl auth init"
        exit 1
    fi
    echo "✓ Authenticated"
    
    # Step 2: Create app spec
    echo "Step 2: Creating app specification..."
    cat > do-app-spec.yaml <<EOF
name: $APP_NAME
region: $REGION
services:
  - name: web
    image:
      registry_type: DOCKER_HUB
      registry: $DOCKER_USERNAME
      repository: $APP_NAME
      tag: latest
    instance_count: 1
    instance_size_slug: basic-xxs
    http_port: 8080
    health_check:
      http_path: /health
    envs:
      - key: PORT
        value: "8080"
      - key: ENVIRONMENT
        value: "production"
      - key: VERSION
        value: "1.0.0"
    routes:
      - path: /
EOF
    
    # Step 3: Create app
    echo "Step 3: Creating/updating app..."
    doctl apps create --spec do-app-spec.yaml
    
    # Step 4: Get URL
    echo "Step 4: Retrieving app URL..."
    APP_ID=$(doctl apps list --format ID --no-header | head -n 1)
    APP_URL=$(doctl apps get $APP_ID --format DefaultIngress --no-header)
    
    echo "=========================================="
    echo "✅ Deployment Complete!"
    echo "=========================================="
    echo "App URL: https://$APP_URL"
    echo "Dashboard: https://cloud.digitalocean.com/apps/$APP_ID"
    echo "=========================================="
    
else
    echo "⚠️  DigitalOcean CLI not installed"
    echo ""
    echo "=========================================="
    echo "Web-Based Deployment (Recommended)"
    echo "=========================================="
    echo ""
    echo "1. Visit: https://cloud.digitalocean.com/apps"
    echo "2. Click 'Create App'"
    echo "3. Select 'Docker Hub'"
    echo "4. Enter:"
    echo "   Repository: $IMAGE"
    echo "   Tag: latest"
    echo ""
    echo "5. Configure:"
    echo "   - App Name: $APP_NAME"
    echo "   - Region: $REGION (New York, San Francisco, etc.)"
    echo "   - Size: Basic (\\$5/mo) or Professional (\\$12/mo)"
    echo ""
    echo "6. Environment Variables:"
    echo "   PORT=8080"
    echo "   ENVIRONMENT=production"
    echo "   VERSION=1.0.0"
    echo ""
    echo "7. Health Check:"
    echo "   Path: /health"
    echo "   Port: 8080"
    echo ""
    echo "8. Click 'Create Resources'"
    echo ""
    echo "=========================================="
    echo "DigitalOcean Features:"
    echo "=========================================="
    echo "✓ Automatic HTTPS"
    echo "✓ Global CDN"
    echo "✓ Auto-deploy on image updates"
    echo "✓ Built-in monitoring"
    echo "✓ Zero-downtime deployments"
    echo "✓ Generous free tier (\\$200 credit)"
    echo ""
    echo "=========================================="
    echo "CLI Installation (Optional):"
    echo "=========================================="
    echo ""
    echo "Windows:"
    echo "  choco install doctl"
    echo ""
    echo "Or download from:"
    echo "  https://github.com/digitalocean/doctl/releases"
    echo ""
    echo "After installation:"
    echo "  doctl auth init"
    echo "  ./deploy-to-digitalocean.sh"
    echo "=========================================="
fi
