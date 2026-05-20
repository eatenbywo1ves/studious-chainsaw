#!/bin/bash

# Deployment script for Catalytic Lattice Computing on Kubernetes
# Supports: minikube, Docker Desktop, kind, and cloud providers

set -e

echo "=========================================="
echo "Catalytic Lattice Kubernetes Deployment"
echo "=========================================="

# Configuration
NAMESPACE="catalytic-lattice"
IMAGE_NAME="catalytic-lattice"
IMAGE_TAG="latest"
REGISTRY="" # Set for cloud deployment, e.g., "gcr.io/project-id/"

# Detect Kubernetes environment
detect_k8s_env() {
    if kubectl config current-context | grep -q "minikube"; then
        echo "Detected: Minikube"
        K8S_ENV="minikube"
    elif kubectl config current-context | grep -q "docker-desktop"; then
        echo "Detected: Docker Desktop"
        K8S_ENV="docker-desktop"
    elif kubectl config current-context | grep -q "kind"; then
        echo "Detected: kind"
        K8S_ENV="kind"
    else
        echo "Detected: Cloud/Other Kubernetes"
        K8S_ENV="cloud"
    fi
}

# Build Docker image
build_image() {
    echo ""
    echo "Building Docker image..."
    docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
    
    if [ -n "$REGISTRY" ]; then
        docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}
        docker push ${REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}
        echo "Image pushed to registry: ${REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}"
    fi
}

# Load image to local Kubernetes
load_image_local() {
    case $K8S_ENV in
        minikube)
            echo "Loading image to Minikube..."
            minikube image load ${IMAGE_NAME}:${IMAGE_TAG}
            ;;
        kind)
            echo "Loading image to kind..."
            kind load docker-image ${IMAGE_NAME}:${IMAGE_TAG}
            ;;
        docker-desktop)
            echo "Image already available to Docker Desktop"
            ;;
        *)
            echo "Using registry image for cloud deployment"
            ;;
    esac
}

# Apply Kubernetes manifests
deploy_to_k8s() {
    echo ""
    echo "Deploying to Kubernetes..."
    
    # Create namespace and configs
    echo "Creating namespace and configurations..."
    kubectl apply -f k8s-namespace.yaml
    
    # Wait for namespace to be ready
    kubectl wait --for=condition=Active namespace/${NAMESPACE} --timeout=30s
    
    # Deploy storage
    echo "Setting up storage..."
    kubectl apply -f k8s-storage.yaml
    
    # Deploy services
    echo "Creating services..."
    kubectl apply -f k8s-services.yaml
    
    # Deploy applications
    echo "Deploying applications..."
    kubectl apply -f k8s-deployments.yaml
    
    echo ""
    echo "Waiting for deployments to be ready..."
    kubectl -n ${NAMESPACE} wait --for=condition=available --timeout=300s deployment/catalytic-api
    kubectl -n ${NAMESPACE} wait --for=condition=available --timeout=300s deployment/catalytic-worker
    kubectl -n ${NAMESPACE} wait --for=condition=available --timeout=300s deployment/redis
}

# Setup port forwarding for local access
setup_port_forward() {
    if [ "$K8S_ENV" != "cloud" ]; then
        echo ""
        echo "Setting up port forwarding for local access..."
        
        # Kill any existing port-forward processes
        pkill -f "kubectl.*port-forward.*catalytic" || true
        
        # Start port forwarding in background
        kubectl -n ${NAMESPACE} port-forward service/catalytic-api-service 8000:80 &
        PF_PID=$!
        echo "API available at: http://localhost:8000"
        echo "Port forward PID: $PF_PID"
        
        # Save PID for later cleanup
        echo $PF_PID > .port-forward.pid
    fi
}

# Get service URLs
get_service_urls() {
    echo ""
    echo "Service URLs:"
    echo "============="
    
    case $K8S_ENV in
        minikube)
            API_URL=$(minikube service catalytic-api-service -n ${NAMESPACE} --url)
            echo "API: $API_URL"
            ;;
        docker-desktop|kind)
            echo "API: http://localhost:8000 (via port-forward)"
            ;;
        cloud)
            API_IP=$(kubectl -n ${NAMESPACE} get service catalytic-api-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
            if [ -n "$API_IP" ]; then
                echo "API: http://$API_IP"
            else
                echo "Waiting for LoadBalancer IP..."
                echo "Run: kubectl -n ${NAMESPACE} get service catalytic-api-service"
            fi
            ;;
    esac
}

# Check deployment status
check_status() {
    echo ""
    echo "Deployment Status:"
    echo "=================="
    kubectl -n ${NAMESPACE} get deployments
    echo ""
    kubectl -n ${NAMESPACE} get pods
    echo ""
    kubectl -n ${NAMESPACE} get services
}

# Run health check
health_check() {
    echo ""
    echo "Running health check..."
    
    if [ "$K8S_ENV" != "cloud" ]; then
        sleep 5  # Wait for port-forward to establish
        HEALTH_STATUS=$(curl -s http://localhost:8000/health | python -m json.tool 2>/dev/null || echo "Failed")
        echo "Health check response:"
        echo "$HEALTH_STATUS"
    fi
}

# Main deployment flow
main() {
    detect_k8s_env
    
    # Check prerequisites
    echo ""
    echo "Checking prerequisites..."
    command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required but not installed. Aborting." >&2; exit 1; }
    
    # Build and load image
    build_image
    load_image_local
    
    # Deploy to Kubernetes
    deploy_to_k8s
    
    # Setup access
    setup_port_forward
    get_service_urls
    
    # Verify deployment
    check_status
    health_check
    
    echo ""
    echo "=========================================="
    echo "Deployment Complete!"
    echo "=========================================="
    echo ""
    echo "Useful commands:"
    echo "  View logs:        kubectl -n ${NAMESPACE} logs -f deployment/catalytic-api"
    echo "  Scale API:        kubectl -n ${NAMESPACE} scale deployment/catalytic-api --replicas=5"
    echo "  View metrics:     kubectl -n ${NAMESPACE} top pods"
    echo "  Delete all:       kubectl delete namespace ${NAMESPACE}"
    echo ""
    echo "Dashboard:"
    if [ "$K8S_ENV" = "minikube" ]; then
        echo "  Run: minikube dashboard"
    else
        echo "  Run: kubectl -n ${NAMESPACE} port-forward service/grafana 3000:3000"
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -f .port-forward.pid ]; then
        kill $(cat .port-forward.pid) 2>/dev/null || true
        rm .port-forward.pid
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Run main deployment
main

echo ""
echo "Press Ctrl+C to stop port forwarding and exit"
wait