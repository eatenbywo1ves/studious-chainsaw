#!/bin/bash
# ================================================================
# Database Restart Fix Deployment Script
# Applies updated health probe configurations to stop restart loops
# ================================================================

set -e  # Exit on error

NAMESPACE="catalytic-staging"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to wait for user confirmation
confirm() {
    read -p "$1 (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Operation cancelled by user"
        exit 0
    fi
}

# Function to check if kubectl is available
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl first."
        exit 1
    fi
    log_success "kubectl is available"
}

# Function to verify cluster connectivity
check_cluster() {
    log_info "Checking cluster connectivity..."
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    log_success "Connected to cluster"
}

# Function to check namespace exists
check_namespace() {
    log_info "Checking namespace: $NAMESPACE"
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace $NAMESPACE does not exist"
        exit 1
    fi
    log_success "Namespace exists"
}

# Function to get current restart counts
get_restart_counts() {
    log_info "Current pod status:"
    kubectl get pods -n "$NAMESPACE" -o wide | grep -E "NAME|postgres-0|redis-0"
    echo ""
}

# Function to validate YAML files
validate_yaml() {
    local file=$1
    log_info "Validating $file..."

    if [ ! -f "$file" ]; then
        log_error "File not found: $file"
        exit 1
    fi

    # Dry-run to validate
    if ! kubectl apply -f "$file" --dry-run=client &> /dev/null; then
        log_error "Invalid YAML in $file"
        exit 1
    fi

    log_success "YAML validation passed: $file"
}

# Function to apply configuration
apply_config() {
    local file=$1
    local resource_name=$2

    log_info "Applying configuration from $file..."

    # Show what will change
    log_info "Configuration diff:"
    kubectl diff -f "$file" 2>/dev/null || true
    echo ""

    confirm "Apply this configuration to $NAMESPACE?"

    # Apply the configuration
    kubectl apply -f "$file"
    log_success "Configuration applied: $resource_name"
}

# Function to verify startup probe was added
verify_startup_probe() {
    local resource=$1
    local resource_name=$2

    log_info "Verifying startup probe for $resource_name..."

    local probe_config=$(kubectl get "$resource" "$resource_name" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].startupProbe}')

    if [ -z "$probe_config" ] || [ "$probe_config" == "{}" ]; then
        log_error "Startup probe NOT found for $resource_name"
        return 1
    fi

    log_success "Startup probe configured for $resource_name"

    # Show the probe configuration
    log_info "Startup probe details:"
    kubectl get "$resource" "$resource_name" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].startupProbe}' | jq '.'
    echo ""
}

# Function to monitor pod status
monitor_pods() {
    log_info "Monitoring pod status (Ctrl+C to stop)..."
    watch -n 5 "kubectl get pods -n $NAMESPACE -o wide | grep -E 'NAME|postgres-0|redis-0'"
}

# Function to perform rolling restart
rolling_restart() {
    local resource=$1
    local resource_name=$2

    log_warning "Performing rolling restart of $resource_name..."
    confirm "This will restart the pod. Continue?"

    kubectl rollout restart "$resource" "$resource_name" -n "$NAMESPACE"

    log_info "Waiting for rollout to complete..."
    kubectl rollout status "$resource" "$resource_name" -n "$NAMESPACE" --timeout=5m

    log_success "Rolling restart completed for $resource_name"
}

# Main execution
main() {
    log_info "======================================================"
    log_info "Database Restart Fix Deployment"
    log_info "Namespace: $NAMESPACE"
    log_info "======================================================"
    echo ""

    # Pre-flight checks
    check_kubectl
    check_cluster
    check_namespace

    # Show current status
    get_restart_counts

    log_warning "This script will:"
    log_warning "1. Apply updated health probe configurations (startupProbe)"
    log_warning "2. Verify the configurations were applied"
    log_warning "3. Optionally perform rolling restarts"
    echo ""

    confirm "Proceed with deployment?"

    # Phase 1: Apply PostgreSQL configuration
    log_info ""
    log_info "====== Phase 1: PostgreSQL Configuration ======"
    validate_yaml "$K8S_DIR/03-postgres.yaml"
    apply_config "$K8S_DIR/03-postgres.yaml" "postgres"
    verify_startup_probe "statefulset" "postgres"

    # Phase 2: Apply Redis configuration
    log_info ""
    log_info "====== Phase 2: Redis Configuration ======"
    validate_yaml "$K8S_DIR/04-redis.yaml"
    apply_config "$K8S_DIR/04-redis.yaml" "redis"
    verify_startup_probe "statefulset" "redis"

    # Phase 3: Optional rolling restart
    log_info ""
    log_info "====== Phase 3: Rolling Restart (Optional) ======"
    log_warning "Configuration has been applied but will only take effect after pod restart."
    echo ""

    read -p "Perform rolling restart now? (y/n/later): " -n 1 -r RESTART_CHOICE
    echo ""

    case $RESTART_CHOICE in
        [Yy])
            rolling_restart "statefulset" "postgres"
            rolling_restart "statefulset" "redis"

            log_info ""
            log_success "======================================================"
            log_success "Deployment Complete!"
            log_success "======================================================"
            get_restart_counts

            log_info ""
            log_info "Monitor pods with: kubectl get pods -n $NAMESPACE -w"
            log_info "Check events with: kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp'"
            ;;
        [Ll])
            log_info ""
            log_info "To manually restart later, run:"
            log_info "  kubectl rollout restart statefulset postgres -n $NAMESPACE"
            log_info "  kubectl rollout restart statefulset redis -n $NAMESPACE"
            ;;
        *)
            log_warning "Restart skipped. Pods will use new configuration on next restart."
            ;;
    esac

    # Monitoring option
    log_info ""
    read -p "Start monitoring pods? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        monitor_pods
    fi

    log_info ""
    log_success "Script completed successfully!"
}

# Run main function
main "$@"
