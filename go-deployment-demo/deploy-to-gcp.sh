#!/bin/bash
# Deploy go-deployment-demo to Google Cloud Run
# Prerequisites: Google Cloud SDK installed and authenticated

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-your-project-id}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="go-deployment-demo"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:1.0.0"

echo "=========================================="
echo "GCP Cloud Run Deployment Script"
echo "=========================================="
echo "Project ID: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo "Image: $IMAGE_NAME"
echo "=========================================="

# Step 1: Authenticate with GCP (if not already authenticated)
echo "Step 1: Checking GCP authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    echo "Not authenticated. Running gcloud auth login..."
    gcloud auth login
fi

# Step 2: Set the project
echo "Step 2: Setting GCP project..."
gcloud config set project "$PROJECT_ID"

# Step 3: Enable required APIs
echo "Step 3: Enabling required GCP APIs..."
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Step 4: Configure Docker to use gcloud as credential helper
echo "Step 4: Configuring Docker authentication..."
gcloud auth configure-docker

# Step 5: Tag the existing Docker image for GCR
echo "Step 5: Tagging Docker image for GCR..."
docker tag go-deployment-demo:1.0.0 "$IMAGE_NAME"

# Step 6: Push image to Google Container Registry
echo "Step 6: Pushing image to GCR..."
docker push "$IMAGE_NAME"

# Step 7: Deploy to Cloud Run
echo "Step 7: Deploying to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
    --image "$IMAGE_NAME" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --port 8080 \
    --memory 128Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 60s \
    --set-env-vars "PORT=8080,ENV=production"

# Step 8: Get the service URL
echo "Step 8: Retrieving service URL..."
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --platform managed \
    --region "$REGION" \
    --format "value(status.url)")

echo "=========================================="
echo "✅ Deployment Complete!"
echo "=========================================="
echo "Service URL: $SERVICE_URL"
echo ""
echo "Test endpoints:"
echo "  Health:    $SERVICE_URL/health"
echo "  Readiness: $SERVICE_URL/ready"
echo "  Metrics:   $SERVICE_URL/metrics"
echo "  Home:      $SERVICE_URL/"
echo "=========================================="

# Optional: Run health check
echo ""
read -p "Run health check? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running health check..."
    curl -s "$SERVICE_URL/health" | jq .
fi
