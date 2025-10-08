#!/bin/bash
# Deploy go-deployment-demo to Render.com
# Render supports Docker deployments via web interface (no CLI required)

set -e

# Configuration
SERVICE_NAME="go-deployment-demo"
DOCKER_USERNAME="${DOCKER_USERNAME:-your-dockerhub-username}"
IMAGE="${DOCKER_USERNAME}/${SERVICE_NAME}:latest"

echo "=========================================="
echo "Render.com Deployment Guide"
echo "=========================================="
echo "Service: $SERVICE_NAME"
echo "Image: $IMAGE"
echo "=========================================="
echo ""
echo "Render.com offers web-based deployment (no CLI installation required)"
echo ""
echo "=========================================="
echo "Web-Based Deployment Steps:"
echo "=========================================="
echo ""
echo "1. Visit: https://render.com"
echo "2. Sign up/Login (free tier available)"
echo "3. Click 'New +' → 'Web Service'"
echo "4. Select 'Existing Image'"
echo "5. Enter Docker Hub image:"
echo "   Image URL: $IMAGE"
echo ""
echo "6. Configure Service:"
echo "   - Name: $SERVICE_NAME"
echo "   - Region: Oregon (US West) or Frankfurt (EU)"
echo "   - Instance Type: Free (or Starter \$7/mo)"
echo ""
echo "7. Environment Variables:"
echo "   PORT=8080"
echo "   ENVIRONMENT=production"
echo "   VERSION=1.0.0"
echo ""
echo "8. Advanced Settings:"
echo "   - Port: 8080"
echo "   - Health Check Path: /health"
echo "   - Auto-Deploy: Yes"
echo ""
echo "9. Click 'Create Web Service'"
echo ""
echo "=========================================="
echo "Render Features:"
echo "=========================================="
echo "✓ Automatic HTTPS (TLS/SSL)"
echo "✓ Global CDN"
echo "✓ Auto-deploy on Docker Hub updates"
echo "✓ Zero-downtime deployments"
echo "✓ Built-in metrics and logging"
echo "✓ Free tier available (750 hours/month)"
echo ""
echo "=========================================="
echo "Post-Deployment:"
echo "=========================================="
echo "Your service will be available at:"
echo "https://${SERVICE_NAME}.onrender.com"
echo ""
echo "Health check:"
echo "curl https://${SERVICE_NAME}.onrender.com/health"
echo ""
echo "=========================================="
echo ""
echo "Alternative: render.yaml Configuration"
echo "=========================================="
cat << 'EOF'

A render.yaml file has been created for infrastructure-as-code deployment.
You can also deploy by:

1. Push code to GitHub
2. Connect Render to your GitHub repo
3. Render auto-detects render.yaml and deploys

EOF
echo "=========================================="
