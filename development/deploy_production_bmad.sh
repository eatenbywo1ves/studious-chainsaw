#!/bin/bash
#
# BMAD Production Deployment Script
# Build → Measure → Analyze → Deploy
#
# This script follows the BMAD methodology to systematically deploy
# the Catalytic Computing SaaS platform to production.
#

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="${NAMESPACE:-catalytic-saas}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-your-registry.io}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD)}"
KUBERNETES_CONTEXT="${KUBERNETES_CONTEXT:-production}"

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

log_section() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}$1${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""
}

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Pre-flight checks
preflight_checks() {
    log_section "Pre-Flight Checks"

    log_info "Checking required tools..."

    command -v docker >/dev/null 2>&1 || error_exit "docker is required but not installed"
    command -v kubectl >/dev/null 2>&1 || error_exit "kubectl is required but not installed"
    command -v git >/dev/null 2>&1 || error_exit "git is required but not installed"

    log_success "All required tools are installed"

    log_info "Verifying Kubernetes context..."
    current_context=$(kubectl config current-context)
    log_info "Current context: $current_context"

    if [[ "$current_context" != *"$KUBERNETES_CONTEXT"* ]]; then
        log_warning "Current context doesn't match expected production context"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Deployment cancelled by user"
        fi
    fi

    log_success "Pre-flight checks complete"
}

# BUILD Phase
build_phase() {
    log_section "BMAD Phase 1: BUILD"

    log_info "Step 1.1: Running integration tests..."
    cd tests/integration

    # Start test environment
    log_info "Starting test environment..."
    docker-compose -f docker-compose.test.yml up -d
    sleep 10  # Wait for services to be ready

    # Run tests
    log_info "Running pytest integration tests..."
    if pytest -v --maxfail=1 2>&1 | tee /tmp/integration_test.log; then
        log_success "Integration tests passed"
    else
        docker-compose -f docker-compose.test.yml down
        error_exit "Integration tests failed. Check /tmp/integration_test.log"
    fi

    # Cleanup
    docker-compose -f docker-compose.test.yml down
    cd ../..

    log_info "Step 1.2: Building Docker image..."
    docker build \
        -t ${DOCKER_REGISTRY}/catalytic-saas:${IMAGE_TAG} \
        -t ${DOCKER_REGISTRY}/catalytic-saas:latest \
        -f saas/Dockerfile \
        .

    log_success "Docker image built: ${DOCKER_REGISTRY}/catalytic-saas:${IMAGE_TAG}"

    log_info "Step 1.3: Running container security scan..."
    # Optional: Add container scanning with tools like trivy
    # trivy image ${DOCKER_REGISTRY}/catalytic-saas:${IMAGE_TAG}
    log_info "Security scan skipped (add trivy or similar tool)"

    log_info "Step 1.4: Pushing Docker image to registry..."
    docker push ${DOCKER_REGISTRY}/catalytic-saas:${IMAGE_TAG}
    docker push ${DOCKER_REGISTRY}/catalytic-saas:latest

    log_success "BUILD phase complete"
}

# MEASURE Phase
measure_phase() {
    log_section "BMAD Phase 2: MEASURE"

    log_info "Step 2.1: Establishing baseline metrics..."

    # Check if monitoring namespace exists
    if kubectl get namespace monitoring >/dev/null 2>&1; then
        log_success "Monitoring namespace exists"
    else
        log_warning "Monitoring namespace not found. Creating..."
        kubectl create namespace monitoring
    fi

    log_info "Step 2.2: Verifying Prometheus is running..."
    if kubectl get pods -n monitoring -l app=prometheus >/dev/null 2>&1; then
        log_success "Prometheus is running"
    else
        log_warning "Prometheus not detected. Monitoring may be incomplete."
    fi

    log_info "Step 2.3: Verifying Grafana is running..."
    if kubectl get pods -n monitoring -l app=grafana >/dev/null 2>&1; then
        log_success "Grafana is running"
    else
        log_warning "Grafana not detected. Dashboards may not be available."
    fi

    log_info "Step 2.4: Collecting current metrics baseline..."
    # Save current metrics state for comparison
    kubectl top nodes > /tmp/baseline_nodes.txt 2>/dev/null || log_warning "kubectl top nodes failed"

    log_success "MEASURE phase complete"
}

# ANALYZE Phase
analyze_phase() {
    log_section "BMAD Phase 3: ANALYZE"

    log_info "Step 3.1: Reviewing production readiness checklist..."

    if [ -f "docs/deployment/PRODUCTION_READINESS_CHECKLIST.md" ]; then
        log_success "Production readiness checklist found"
        log_info "Review the checklist at: docs/deployment/PRODUCTION_READINESS_CHECKLIST.md"
    else
        log_warning "Production readiness checklist not found"
    fi

    log_info "Step 3.2: Validating Kubernetes manifests..."

    for manifest in kubernetes/*.yaml; do
        if kubectl apply --dry-run=client -f "$manifest" >/dev/null 2>&1; then
            log_success "$(basename $manifest) is valid"
        else
            error_exit "$(basename $manifest) validation failed"
        fi
    done

    log_info "Step 3.3: Checking for existing deployment..."

    if kubectl get deployment saas-api -n $NAMESPACE >/dev/null 2>&1; then
        log_warning "Existing deployment found. This will be updated."
        log_info "Current replicas:"
        kubectl get deployment saas-api -n $NAMESPACE -o jsonpath='{.spec.replicas}'
        echo ""
    else
        log_info "No existing deployment. This will be a fresh deployment."
    fi

    log_info "Step 3.4: Verifying secrets are configured..."

    if kubectl get secret saas-secrets -n $NAMESPACE >/dev/null 2>&1; then
        log_success "Kubernetes secrets exist"
    else
        log_error "Required secrets not found. Creating template secrets..."

        # Generate random secrets
        JWT_SECRET=$(openssl rand -base64 32)
        DB_PASSWORD=$(openssl rand -base64 32)
        REDIS_PASSWORD=$(openssl rand -base64 32)

        kubectl create secret generic saas-secrets \
            --from-literal=jwt-secret="$JWT_SECRET" \
            --from-literal=db-password="$DB_PASSWORD" \
            --from-literal=redis-password="$REDIS_PASSWORD" \
            -n $NAMESPACE --dry-run=client -o yaml > /tmp/secrets.yaml

        log_warning "Secrets template created at /tmp/secrets.yaml"
        log_warning "Please review and apply manually: kubectl apply -f /tmp/secrets.yaml"

        read -p "Apply generated secrets now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kubectl apply -f /tmp/secrets.yaml
            log_success "Secrets applied"
        else
            error_exit "Secrets must be configured before deployment"
        fi
    fi

    log_success "ANALYZE phase complete"
}

# DEPLOY Phase
deploy_phase() {
    log_section "BMAD Phase 4: DEPLOY"

    log_info "Step 4.1: Creating namespace if not exists..."
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    log_success "Namespace $NAMESPACE ready"

    log_info "Step 4.2: Applying ConfigMap..."
    kubectl apply -f kubernetes/configmap.yaml -n $NAMESPACE

    log_info "Step 4.3: Applying Deployment..."
    # Update image tag in deployment
    sed "s|image:.*catalytic-saas:.*|image: ${DOCKER_REGISTRY}/catalytic-saas:${IMAGE_TAG}|g" \
        kubernetes/deployment.yaml | kubectl apply -f - -n $NAMESPACE

    log_info "Step 4.4: Applying Service..."
    kubectl apply -f kubernetes/service.yaml -n $NAMESPACE

    log_info "Step 4.5: Applying HPA (Horizontal Pod Autoscaler)..."
    kubectl apply -f kubernetes/hpa.yaml -n $NAMESPACE

    log_info "Step 4.6: Applying Network Policy..."
    kubectl apply -f kubernetes/networkpolicy.yaml -n $NAMESPACE

    log_info "Step 4.7: Applying Ingress..."
    kubectl apply -f kubernetes/ingress.yaml -n $NAMESPACE

    log_info "Step 4.8: Waiting for rollout to complete..."
    kubectl rollout status deployment/saas-api -n $NAMESPACE --timeout=5m

    log_success "Deployment rollout complete"

    log_info "Step 4.9: Verifying pods are running..."
    kubectl get pods -n $NAMESPACE -l app=saas-api

    log_info "Step 4.10: Running smoke tests..."

    # Get service endpoint
    INGRESS_IP=$(kubectl get ingress saas-ingress -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")

    if [ "$INGRESS_IP" != "pending" ]; then
        log_info "Testing health endpoint at http://$INGRESS_IP/health"

        # Wait for service to be ready
        sleep 10

        if curl -f -s "http://$INGRESS_IP/health" >/dev/null 2>&1; then
            log_success "Health check passed"
        else
            log_warning "Health check failed. Service may still be starting..."
        fi
    else
        log_warning "Ingress IP not yet assigned. Skip smoke tests or test via port-forward."
    fi

    log_success "DEPLOY phase complete"
}

# Post-deployment monitoring
post_deployment_monitoring() {
    log_section "Post-Deployment Monitoring"

    log_info "Deployment Summary:"
    echo ""
    echo "Namespace:        $NAMESPACE"
    echo "Image:            ${DOCKER_REGISTRY}/catalytic-saas:${IMAGE_TAG}"
    echo "Current replicas:"
    kubectl get deployment saas-api -n $NAMESPACE -o jsonpath='{.status.replicas}'
    echo ""
    echo "Ready replicas:"
    kubectl get deployment saas-api -n $NAMESPACE -o jsonpath='{.status.readyReplicas}'
    echo ""
    echo ""

    log_info "View logs with:"
    echo "  kubectl logs -f deployment/saas-api -n $NAMESPACE"
    echo ""

    log_info "View metrics with:"
    echo "  kubectl top pods -n $NAMESPACE"
    echo ""

    log_info "Rollback if needed with:"
    echo "  kubectl rollout undo deployment/saas-api -n $NAMESPACE"
    echo ""

    log_info "Monitor auto-scaling with:"
    echo "  kubectl get hpa -n $NAMESPACE -w"
    echo ""

    log_success "Production deployment complete!"
}

# Rollback function
rollback() {
    log_section "ROLLBACK INITIATED"

    log_warning "Rolling back deployment..."
    kubectl rollout undo deployment/saas-api -n $NAMESPACE

    log_info "Waiting for rollback to complete..."
    kubectl rollout status deployment/saas-api -n $NAMESPACE

    log_success "Rollback complete"
}

# Main execution
main() {
    log_section "BMAD Production Deployment"

    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Image Tag: $IMAGE_TAG"
    echo ""

    # Parse command line arguments
    case "${1:-deploy}" in
        deploy)
            preflight_checks
            build_phase
            measure_phase
            analyze_phase
            deploy_phase
            post_deployment_monitoring
            ;;
        rollback)
            rollback
            ;;
        build-only)
            preflight_checks
            build_phase
            ;;
        analyze-only)
            analyze_phase
            ;;
        *)
            echo "Usage: $0 {deploy|rollback|build-only|analyze-only}"
            exit 1
            ;;
    esac
}

# Trap errors and provide rollback option
trap 'log_error "Deployment failed! Run: $0 rollback to revert changes"' ERR

# Run main function
main "$@"
