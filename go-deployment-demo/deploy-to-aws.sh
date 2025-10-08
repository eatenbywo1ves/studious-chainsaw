#!/bin/bash
# Deploy go-deployment-demo to AWS ECS/Fargate
# Requires AWS CLI to be installed

set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
CLUSTER_NAME="go-demo-cluster"
SERVICE_NAME="go-deployment-demo"
TASK_NAME="go-deployment-demo-task"
ECR_REPO="go-deployment-demo"
IMAGE_TAG="1.0.0"

echo "=========================================="
echo "AWS ECS/Fargate Deployment Script"
echo "=========================================="
echo "Region: $AWS_REGION"
echo "Cluster: $CLUSTER_NAME"
echo "Service: $SERVICE_NAME"
echo "=========================================="

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not installed"
    echo ""
    echo "=========================================="
    echo "Installation Instructions:"
    echo "=========================================="
    echo ""
    echo "Windows:"
    echo "  msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi"
    echo ""
    echo "Or download from:"
    echo "  https://aws.amazon.com/cli/"
    echo ""
    echo "After installation:"
    echo "  aws configure"
    echo "  ./deploy-to-aws.sh"
    echo ""
    echo "=========================================="
    exit 1
fi

echo "✓ AWS CLI found"

# Step 1: Authenticate
echo "Step 1: Checking AWS authentication..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo "ERROR: Not authenticated. Run: aws configure"
    exit 1
fi
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "✓ Authenticated (Account: $AWS_ACCOUNT_ID)"

# Step 2: Create ECR repository
echo "Step 2: Creating ECR repository..."
aws ecr describe-repositories --repository-names $ECR_REPO --region $AWS_REGION &> /dev/null || \
    aws ecr create-repository --repository-name $ECR_REPO --region $AWS_REGION
echo "✓ ECR repository ready"

# Step 3: Login to ECR
echo "Step 3: Logging in to ECR..."
aws ecr get-login-password --region $AWS_REGION | \
    docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
echo "✓ ECR login successful"

# Step 4: Tag and push image
echo "Step 4: Pushing image to ECR..."
ECR_IMAGE="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO:$IMAGE_TAG"
docker tag go-deployment-demo:1.0.0 $ECR_IMAGE
docker push $ECR_IMAGE
echo "✓ Image pushed"

# Step 5: Create ECS cluster
echo "Step 5: Creating ECS cluster..."
aws ecs describe-clusters --clusters $CLUSTER_NAME --region $AWS_REGION &> /dev/null || \
    aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $AWS_REGION
echo "✓ Cluster ready"

# Step 6: Register task definition
echo "Step 6: Registering task definition..."
cat > task-definition.json <<EOF
{
  "family": "$TASK_NAME",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "$SERVICE_NAME",
      "image": "$ECR_IMAGE",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "PORT", "value": "8080"},
        {"name": "ENVIRONMENT", "value": "production"},
        {"name": "VERSION", "value": "1.0.0"}
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/$SERVICE_NAME",
          "awslogs-region": "$AWS_REGION",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
EOF

aws ecs register-task-definition --cli-input-json file://task-definition.json --region $AWS_REGION
echo "✓ Task definition registered"

# Step 7: Create service
echo "Step 7: Creating ECS service..."
# Note: This requires VPC and subnet configuration
echo "⚠️  Service creation requires VPC/subnet configuration"
echo "    Run manually with appropriate VPC settings"

echo "=========================================="
echo "✅ Image Deployed to ECR!"
echo "=========================================="
echo "ECR Image: $ECR_IMAGE"
echo ""
echo "Next steps:"
echo "1. Create VPC and subnets (if not exists)"
echo "2. Create ECS service with load balancer"
echo "3. Configure security groups"
echo ""
echo "See AWS documentation:"
echo "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/getting-started-fargate.html"
echo "=========================================="
