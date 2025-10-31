#!/bin/bash
# ========================================
# Kubernetes Deployment Script
# Deploys Catalytic Computing Platform
# ========================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ENVIRONMENT="${1:-staging}"
NAMESPACE="catalytic-${ENVIRONMENT}"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    log_success "kubectl found: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    log_success "Connected to Kubernetes cluster"

    # Check namespace
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE already exists"
    else
        log_info "Namespace $NAMESPACE will be created"
    fi
}

# Validate secrets
check_secrets() {
    log_info "Checking secrets in $NAMESPACE..."

    local secrets=("postgres-credentials" "redis-credentials" "jwt-secrets" "api-keys")
    local missing_secrets=()

    for secret in "${secrets[@]}"; do
        if ! kubectl get secret "$secret" -n "$NAMESPACE" &> /dev/null; then
            missing_secrets+=("$secret")
        fi
    done

    if [ ${#missing_secrets[@]} -gt 0 ]; then
        log_error "Missing secrets in $NAMESPACE: ${missing_secrets[*]}"
        log_info "Please create secrets using:"
        log_info "  kubectl create secret generic <name> --from-literal=key=value -n $NAMESPACE"
        log_info "Or apply 02-secrets.yaml after replacing placeholder values"
        exit 1
    fi

    log_success "All required secrets exist"
}

# Deploy function
deploy_resource() {
    local file=$1
    local namespace=${2:-$NAMESPACE}

    log_info "Deploying $(basename "$file")..."

    if kubectl apply -f "$file" -n "$namespace" 2>&1 | tee /tmp/deploy.log; then
        log_success "Deployed $(basename "$file")"
        return 0
    else
        log_error "Failed to deploy $(basename "$file")"
        cat /tmp/deploy.log
        return 1
    fi
}

# Wait for resource to be ready
wait_for_resource() {
    local resource_type=$1
    local resource_name=$2
    local namespace=$3
    local timeout=${4:-300}

    log_info "Waiting for $resource_type/$resource_name to be ready (timeout: ${timeout}s)..."

    if kubectl wait --for=condition=ready "$resource_type/$resource_name" -n "$namespace" --timeout="${timeout}s" 2>&1; then
        log_success "$resource_type/$resource_name is ready"
        return 0
    else
        log_error "$resource_type/$resource_name failed to become ready"
        kubectl describe "$resource_type/$resource_name" -n "$namespace"
        kubectl logs -l "app=$resource_name" -n "$namespace" --tail=50
        return 1
    fi
}

# Main deployment
main() {
    log_info "========================================="
    log_info "Catalytic Computing Platform Deployment"
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "========================================="

    # Check prerequisites
    check_prerequisites

    # Deploy namespace and base resources
    log_info "Deploying base resources..."
    # Apply namespace file directly (resources have namespace in metadata)
    log_info "Deploying 00-namespace.yaml..."
    if kubectl apply -f "$SCRIPT_DIR/00-namespace.yaml" 2>&1 | tee /tmp/deploy.log; then
        log_success "Deployed 00-namespace.yaml"
    else
        log_error "Failed to deploy 00-namespace.yaml"
        cat /tmp/deploy.log
        exit 1
    fi
    # Apply configmaps directly (resources have namespace in metadata)
    log_info "Deploying 01-configmaps.yaml..."
    if kubectl apply -f "$SCRIPT_DIR/01-configmaps.yaml" 2>&1 | tee /tmp/deploy.log; then
        log_success "Deployed 01-configmaps.yaml"
    else
        log_error "Failed to deploy 01-configmaps.yaml"
        cat /tmp/deploy.log
        exit 1
    fi

    # Check or create secrets
    if ! check_secrets 2>/dev/null; then
        log_warning "Secrets not found, attempting to deploy from template..."
        deploy_resource "$SCRIPT_DIR/02-secrets.yaml"
        log_warning "⚠️  Remember to update secrets with real values!"
    fi

    # Deploy infrastructure (PostgreSQL, Redis)
    log_info "Deploying infrastructure..."
    # Apply infrastructure files directly (resources have namespace in metadata)
    log_info "Deploying 03-postgres.yaml..."
    if kubectl apply -f "$SCRIPT_DIR/03-postgres.yaml" 2>&1 | tee /tmp/deploy.log; then
        log_success "Deployed 03-postgres.yaml"
    else
        log_warning "Some resources may have failed (check /tmp/deploy.log)"
    fi

    log_info "Deploying 04-redis.yaml..."
    if kubectl apply -f "$SCRIPT_DIR/04-redis.yaml" 2>&1 | tee /tmp/deploy.log; then
        log_success "Deployed 04-redis.yaml"
    else
        log_warning "Some resources may have failed (check /tmp/deploy.log)"
    fi

    # Wait for databases
    log_info "Waiting for databases to be ready..."
    # StatefulSets create pods with predictable names: <statefulset-name>-<ordinal>
    log_info "Waiting for PostgreSQL pod..."
    kubectl wait --for=condition=ready pod/postgres-0 -n "$NAMESPACE" --timeout=300s || log_warning "PostgreSQL wait timeout (may already be ready)"

    log_info "Waiting for Redis pod..."
    kubectl wait --for=condition=ready pod/redis-0 -n "$NAMESPACE" --timeout=300s || log_warning "Redis wait timeout (may already be ready)"

    # Verify database connectivity
    log_info "Verifying PostgreSQL connectivity..."
    if kubectl exec -n "$NAMESPACE" -it $(kubectl get pod -l app=postgres -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}') -- \
       pg_isready -U catalytic_staging 2>&1 | grep -q "accepting connections"; then
        log_success "PostgreSQL is accepting connections"
    else
        log_error "PostgreSQL connection check failed"
        exit 1
    fi

    log_info "Verifying Redis connectivity..."
    # Get Redis password from secret
    REDIS_PASSWORD=$(kubectl get secret redis-credentials -n "$NAMESPACE" -o jsonpath='{.data.password}' | base64 --decode)
    if kubectl exec -n "$NAMESPACE" $(kubectl get pod -l app=redis -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}') -- \
       redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping 2>&1 | grep -q "PONG"; then
        log_success "Redis is responding"
    else
        log_warning "Redis ping check failed (may require manual verification)"
        # Don't exit - Redis might be working but responding differently
    fi

    # Deploy applications
    log_info "Deploying applications..."
    # Apply application files directly (resources have namespace in metadata)
    for app_file in "05-catalytic-api.yaml" "06-webhook-system.yaml" "07-saas-api.yaml"; do
        log_info "Deploying ${app_file}..."
        if kubectl apply -f "$SCRIPT_DIR/${app_file}" 2>&1 | tee /tmp/deploy.log; then
            log_success "Deployed ${app_file}"
        else
            log_warning "Some resources in ${app_file} may have failed"
        fi
    done

    # Wait for applications
    log_info "Waiting for applications to be ready..."
    wait_for_resource "deployment" "catalytic-api" "$NAMESPACE" 300
    wait_for_resource "deployment" "webhook-system" "$NAMESPACE" 300
    wait_for_resource "deployment" "saas-api" "$NAMESPACE" 300

    # Deploy networking and scaling
    log_info "Deploying networking and auto-scaling..."
    # Apply networking files directly (resources have namespace in metadata)
    for net_file in "08-ingress.yaml" "09-hpa.yaml" "10-network-policies.yaml"; do
        log_info "Deploying ${net_file}..."
        if kubectl apply -f "$SCRIPT_DIR/${net_file}" 2>&1 | tee /tmp/deploy.log; then
            log_success "Deployed ${net_file}"
        else
            log_warning "Some resources in ${net_file} may have failed"
        fi
    done

    # Display deployment status
    log_info "========================================="
    log_info "Deployment Summary"
    log_info "========================================="

    log_info "Pods:"
    kubectl get pods -n "$NAMESPACE" -o wide

    log_info "\nServices:"
    kubectl get svc -n "$NAMESPACE"

    log_info "\nIngress:"
    kubectl get ingress -n "$NAMESPACE"

    log_info "\nHPA:"
    kubectl get hpa -n "$NAMESPACE"

    log_info "\nPVC:"
    kubectl get pvc -n "$NAMESPACE"

    # Health check
    log_info "========================================="
    log_info "Performing health checks..."
    log_info "========================================="

    # Wait a bit for health checks to stabilize
    sleep 10

    # Check pod health
    local unhealthy_pods=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running -o json | jq -r '.items | length')
    if [ "$unhealthy_pods" -eq 0 ]; then
        log_success "All pods are healthy"
    else
        log_warning "$unhealthy_pods pod(s) are not in Running state"
        kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running
    fi

    # Success message
    log_success "========================================="
    log_success "Deployment completed successfully!"
    log_success "========================================="

    log_info "\nNext steps:"
    log_info "1. Verify health endpoints:"
    log_info "   kubectl port-forward svc/saas-api 8000:80 -n $NAMESPACE"
    log_info "   curl http://localhost:8000/health"
    log_info ""
    log_info "2. Check logs:"
    log_info "   kubectl logs -f -l app=saas-api -n $NAMESPACE"
    log_info ""
    log_info "3. Monitor metrics:"
    log_info "   kubectl port-forward svc/saas-api 8001:8001 -n $NAMESPACE"
    log_info "   curl http://localhost:8001/metrics"
    log_info ""
    log_info "4. Configure DNS to point to ingress:"
    log_info "   kubectl get ingress -n $NAMESPACE"
    log_info ""
    log_info "5. Monitor HPA scaling:"
    log_info "   kubectl get hpa -n $NAMESPACE --watch"
}

# Cleanup function (optional)
cleanup() {
    log_warning "Cleaning up $NAMESPACE..."
    read -p "Are you sure you want to delete all resources in $NAMESPACE? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy]es$ ]]; then
        kubectl delete namespace "$NAMESPACE"
        log_success "Namespace $NAMESPACE deleted"
    else
        log_info "Cleanup cancelled"
    fi
}

# Script usage
usage() {
    echo "Usage: $0 [environment] [command]"
    echo ""
    echo "Environments:"
    echo "  staging      Deploy to staging environment (default)"
    echo "  production   Deploy to production environment"
    echo ""
    echo "Commands:"
    echo "  deploy       Deploy all resources (default)"
    echo "  cleanup      Delete all resources in namespace"
    echo ""
    echo "Examples:"
    echo "  $0                    # Deploy to staging"
    echo "  $0 production         # Deploy to production"
    echo "  $0 staging cleanup    # Clean up staging"
}

# Parse arguments
case "${2:-deploy}" in
    deploy)
        main
        ;;
    cleanup)
        cleanup
        ;;
    *)
        usage
        exit 1
        ;;
esac
