#!/bin/bash
# Deploy go-deployment-demo to Docker Hub
# Makes the image publicly available for cloud deployments

set -e

# Configuration
DOCKER_USERNAME="${DOCKER_USERNAME:-your-dockerhub-username}"
IMAGE_NAME="go-deployment-demo"
VERSION="1.0.0"

echo "=========================================="
echo "Docker Hub Deployment Script"
echo "=========================================="
echo "Username: $DOCKER_USERNAME"
echo "Image: $IMAGE_NAME"
echo "Version: $VERSION"
echo "=========================================="

# Step 1: Check if Docker is running
echo "Step 1: Checking Docker status..."
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running!"
    exit 1
fi
echo "✓ Docker is running"

# Step 2: Check if local image exists
echo "Step 2: Checking local image..."
if ! docker image inspect ${IMAGE_NAME}:${VERSION} > /dev/null 2>&1; then
    echo "ERROR: Local image ${IMAGE_NAME}:${VERSION} not found!"
    echo "Run: docker build -t ${IMAGE_NAME}:${VERSION} ."
    exit 1
fi
echo "✓ Local image found"

# Step 3: Tag image for Docker Hub
echo "Step 3: Tagging image for Docker Hub..."
docker tag ${IMAGE_NAME}:${VERSION} ${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}
docker tag ${IMAGE_NAME}:${VERSION} ${DOCKER_USERNAME}/${IMAGE_NAME}:latest
echo "✓ Image tagged"

# Step 4: Login to Docker Hub (if not already logged in)
echo "Step 4: Checking Docker Hub authentication..."
if ! docker info | grep -q "Username: ${DOCKER_USERNAME}"; then
    echo "Logging in to Docker Hub..."
    docker login
fi
echo "✓ Authenticated"

# Step 5: Push to Docker Hub
echo "Step 5: Pushing to Docker Hub..."
docker push ${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}
docker push ${DOCKER_USERNAME}/${IMAGE_NAME}:latest
echo "✓ Image pushed"

# Step 6: Display results
echo "=========================================="
echo "✅ Deployment Complete!"
echo "=========================================="
echo "Docker Hub URLs:"
echo "  Version: https://hub.docker.com/r/${DOCKER_USERNAME}/${IMAGE_NAME}/tags"
echo "  Pull: docker pull ${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}"
echo ""
echo "Use this image for cloud deployments:"
echo "  Railway: ${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
echo "  Render: ${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
echo "  Fly.io: ${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
echo "=========================================="
