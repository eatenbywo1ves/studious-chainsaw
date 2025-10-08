#!/bin/bash
# Deploy go-deployment-demo to Azure Container Instances
# Requires Azure CLI to be installed

set -e

# Configuration
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-go-demo-rg}"
LOCATION="${AZURE_LOCATION:-eastus}"
CONTAINER_NAME="go-deployment-demo"
ACR_NAME="${AZURE_ACR_NAME:-godemoreg}"
IMAGE_TAG="1.0.0"

echo "=========================================="
echo "Azure Container Instances Deployment"
echo "=========================================="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo "Container: $CONTAINER_NAME"
echo "=========================================="

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not installed"
    echo ""
    echo "=========================================="
    echo "Installation Instructions:"
    echo "=========================================="
    echo ""
    echo "Windows:"
    echo "  Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\\AzureCLI.msi"
    echo "  Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'"
    echo ""
    echo "Or download from:"
    echo "  https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
    echo ""
    echo "After installation:"
    echo "  az login"
    echo "  ./deploy-to-azure.sh"
    echo ""
    echo "=========================================="
    exit 1
fi

echo "✓ Azure CLI found"

# Step 1: Login
echo "Step 1: Checking Azure authentication..."
if ! az account show &> /dev/null; then
    echo "Logging in to Azure..."
    az login
fi
echo "✓ Authenticated"

# Step 2: Create resource group
echo "Step 2: Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION
echo "✓ Resource group ready"

# Step 3: Create Azure Container Registry
echo "Step 3: Creating Azure Container Registry..."
az acr create --resource-group $RESOURCE_GROUP \
    --name $ACR_NAME \
    --sku Basic \
    --location $LOCATION
echo "✓ ACR created"

# Step 4: Login to ACR
echo "Step 4: Logging in to ACR..."
az acr login --name $ACR_NAME
ACR_LOGIN_SERVER=$(az acr show --name $ACR_NAME --query loginServer --output tsv)
echo "✓ ACR login successful"

# Step 5: Tag and push image
echo "Step 5: Pushing image to ACR..."
ACR_IMAGE="$ACR_LOGIN_SERVER/$CONTAINER_NAME:$IMAGE_TAG"
docker tag go-deployment-demo:1.0.0 $ACR_IMAGE
docker push $ACR_IMAGE
echo "✓ Image pushed"

# Step 6: Enable admin user on ACR
echo "Step 6: Enabling ACR admin user..."
az acr update --name $ACR_NAME --admin-enabled true
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" --output tsv)
echo "✓ Admin user enabled"

# Step 7: Deploy to Container Instances
echo "Step 7: Deploying to Azure Container Instances..."
az container create \
    --resource-group $RESOURCE_GROUP \
    --name $CONTAINER_NAME \
    --image $ACR_IMAGE \
    --registry-login-server $ACR_LOGIN_SERVER \
    --registry-username $ACR_NAME \
    --registry-password $ACR_PASSWORD \
    --dns-name-label $CONTAINER_NAME \
    --ports 8080 \
    --cpu 1 \
    --memory 0.5 \
    --environment-variables PORT=8080 ENVIRONMENT=production VERSION=1.0.0 \
    --location $LOCATION

# Step 8: Get URL
echo "Step 8: Retrieving container URL..."
CONTAINER_FQDN=$(az container show \
    --resource-group $RESOURCE_GROUP \
    --name $CONTAINER_NAME \
    --query ipAddress.fqdn \
    --output tsv)

echo "=========================================="
echo "✅ Deployment Complete!"
echo "=========================================="
echo "Container URL: http://$CONTAINER_FQDN:8080"
echo ""
echo "Test endpoints:"
echo "  curl http://$CONTAINER_FQDN:8080/health"
echo "  curl http://$CONTAINER_FQDN:8080/ready"
echo "  curl http://$CONTAINER_FQDN:8080/metrics"
echo ""
echo "Azure Portal:"
echo "  https://portal.azure.com/#@/resource/subscriptions/*/resourceGroups/$RESOURCE_GROUP"
echo "=========================================="
