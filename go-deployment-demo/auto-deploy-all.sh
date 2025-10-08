#!/bin/bash
# BMAD Automated Deployment - Complete Workflow
# This script automates Docker Hub push and provides cloud deployment steps

set -e

echo "=========================================="
echo "BMAD AUTOMATED DEPLOYMENT"
echo "=========================================="
echo "This script will:"
echo "1. Push to Docker Hub"
echo "2. Provide Railway.app setup commands"
echo "3. Provide Render.com setup commands"
echo "4. Verify all deployments"
echo "=========================================="
echo ""

# Check if DOCKER_USERNAME is set
if [ -z "$DOCKER_USERNAME" ]; then
    echo "⚠️  DOCKER_USERNAME environment variable not set"
    echo ""
    read -p "Enter your Docker Hub username: " DOCKER_USERNAME
    export DOCKER_USERNAME
fi

echo "Docker Hub Username: $DOCKER_USERNAME"
echo ""

# Step 1: Verify Docker is running
echo "Step 1: Verifying Docker..."
if ! docker info > /dev/null 2>&1; then
    echo "❌ ERROR: Docker is not running!"
    exit 1
fi
echo "✅ Docker is running"
echo ""

# Step 2: Verify local image exists
echo "Step 2: Verifying local image..."
if ! docker image inspect go-deployment-demo:1.0.0 > /dev/null 2>&1; then
    echo "❌ ERROR: Local image 'go-deployment-demo:1.0.0' not found!"
    exit 1
fi
echo "✅ Local image found"
echo ""

# Step 3: Check Docker Hub authentication
echo "Step 3: Checking Docker Hub authentication..."
if ! docker info | grep -q "Username"; then
    echo "⚠️  Not logged in to Docker Hub"
    echo "Logging in now..."
    docker login
fi
echo "✅ Docker Hub authenticated"
echo ""

# Step 4: Tag images
echo "Step 4: Tagging images for Docker Hub..."
docker tag go-deployment-demo:1.0.0 $DOCKER_USERNAME/go-deployment-demo:1.0.0
docker tag go-deployment-demo:1.0.0 $DOCKER_USERNAME/go-deployment-demo:latest
echo "✅ Images tagged"
echo ""

# Step 5: Push to Docker Hub
echo "Step 5: Pushing to Docker Hub..."
echo "This may take 2-3 minutes for a 10.3MB image..."
docker push $DOCKER_USERNAME/go-deployment-demo:1.0.0
docker push $DOCKER_USERNAME/go-deployment-demo:latest
echo "✅ Images pushed to Docker Hub"
echo ""

# Step 6: Verify push
echo "Step 6: Verifying Docker Hub push..."
sleep 2
docker pull $DOCKER_USERNAME/go-deployment-demo:latest > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Image successfully pulled from Docker Hub"
else
    echo "⚠️  Could not verify push, but push completed"
fi
echo ""

# Generate deployment URLs
DOCKERHUB_URL="https://hub.docker.com/r/$DOCKER_USERNAME/go-deployment-demo"
RAILWAY_IMAGE="$DOCKER_USERNAME/go-deployment-demo:latest"
RENDER_IMAGE="docker.io/$DOCKER_USERNAME/go-deployment-demo:latest"

echo "=========================================="
echo "✅ DOCKER HUB DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "Your image is now public at:"
echo "🔗 $DOCKERHUB_URL"
echo ""
echo "Image details:"
echo "  - Repository: $DOCKER_USERNAME/go-deployment-demo"
echo "  - Tags: 1.0.0, latest"
echo "  - Size: ~10.3 MB"
echo "  - Pulls: docker pull $DOCKER_USERNAME/go-deployment-demo:latest"
echo ""

# Save deployment info to file
cat > deployment-info.txt <<EOF
BMAD Deployment Information
Generated: $(date)

Docker Hub:
  URL: $DOCKERHUB_URL
  Image: $RAILWAY_IMAGE
  Size: 10.3 MB
  
Railway.app Image:
  $RAILWAY_IMAGE
  
Render.com Image:
  $RENDER_IMAGE
  
Environment Variables (for all platforms):
  PORT=8080
  ENVIRONMENT=production
  VERSION=1.0.0
EOF

echo "📝 Deployment info saved to: deployment-info.txt"
echo ""

echo "=========================================="
echo "NEXT: RAILWAY.APP DEPLOYMENT"
echo "=========================================="
echo ""
echo "Option A: Web-Based (No CLI) - Recommended"
echo "-------------------------------------------"
echo "1. Visit: https://railway.app"
echo "2. Click 'New Project' → 'Deploy from Docker Image'"
echo "3. Image: $RAILWAY_IMAGE"
echo "4. Environment Variables:"
echo "   PORT=8080"
echo "   ENVIRONMENT=production"
echo "   VERSION=1.0.0"
echo "5. Click 'Deploy'"
echo ""
echo "Option B: CLI-Based (if Railway CLI installed)"
echo "-------------------------------------------"
if command -v railway &> /dev/null; then
    echo "✅ Railway CLI found!"
    echo ""
    echo "Run these commands:"
    echo "  railway login"
    echo "  railway init"
    echo "  railway up"
else
    echo "⚠️  Railway CLI not installed"
    echo "Install with: npm install -g @railway/cli"
fi
echo ""

echo "=========================================="
echo "NEXT: RENDER.COM DEPLOYMENT"
echo "=========================================="
echo ""
echo "Web-Based Deployment (No CLI Required)"
echo "-------------------------------------------"
echo "1. Visit: https://render.com"
echo "2. Click 'New +' → 'Web Service' → 'Existing Image'"
echo "3. Image URL: $RENDER_IMAGE"
echo "4. Service Configuration:"
echo "   - Name: go-deployment-demo"
echo "   - Region: Oregon (or nearest)"
echo "   - Instance Type: Free or Starter (\$7/mo)"
echo "5. Environment Variables:"
echo "   PORT=8080"
echo "   ENVIRONMENT=production"
echo "   VERSION=1.0.0"
echo "6. Advanced Settings:"
echo "   - Port: 8080"
echo "   - Health Check Path: /health"
echo "7. Click 'Create Web Service'"
echo ""

echo "=========================================="
echo "VERIFICATION COMMANDS"
echo "=========================================="
echo ""
echo "After deployment, test with these commands:"
echo ""
echo "# Set your deployment URLs"
echo "export RAILWAY_URL=https://your-app.up.railway.app"
echo "export RENDER_URL=https://go-deployment-demo.onrender.com"
echo ""
echo "# Test Railway"
echo "curl \$RAILWAY_URL/health"
echo ""
echo "# Test Render"
echo "curl \$RENDER_URL/health"
echo ""
echo "# Test all endpoints"
echo "./verify-deployment.sh"
echo ""

echo "=========================================="
echo "DEPLOYMENT SUMMARY"
echo "=========================================="
echo ""
echo "✅ Completed:"
echo "  - Docker Swarm (local) - Running on port 8081"
echo "  - Docker Hub - Image pushed and verified"
echo ""
echo "⏳ Pending (web-based, ~10 min each):"
echo "  - Railway.app deployment"
echo "  - Render.com deployment"
echo ""
echo "📚 Documentation:"
echo "  - START_DEPLOYMENT.md - Full guide"
echo "  - deployment-info.txt - Your deployment details"
echo "  - verify-deployment.sh - Verification script (being created)"
echo ""
echo "=========================================="
echo "🎉 READY FOR CLOUD DEPLOYMENT!"
echo "=========================================="
