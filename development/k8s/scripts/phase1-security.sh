#!/bin/bash
# ========================================
# Phase 1: Security Foundation
# Generate secrets and configure secure storage
# ========================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

NAMESPACE="${1:-catalytic-staging}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="${SCRIPT_DIR}/../.secrets-${NAMESPACE}.env"

log_info "========================================="
log_info "Phase 1: Security Foundation"
log_info "Namespace: ${NAMESPACE}"
log_info "========================================="

# Check prerequisites
command -v kubectl >/dev/null 2>&1 || { log_error "kubectl not found"; exit 1; }
command -v openssl >/dev/null 2>&1 || { log_error "openssl not found"; exit 1; }

# Generate strong secrets
log_info "Generating cryptographically strong secrets..."

POSTGRES_USER="catalytic_${NAMESPACE#catalytic-}"
POSTGRES_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')
REDIS_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')
JWT_SECRET=$(openssl rand -hex 64)
API_KEY=$(openssl rand -hex 32)
WEBHOOK_SECRET=$(openssl rand -hex 32)

log_success "Secrets generated"

# Save secrets locally (gitignored)
cat > "${SECRETS_FILE}" <<EOF
# Generated: $(date)
# WARNING: Keep this file secure and never commit to Git

POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
JWT_SECRET=${JWT_SECRET}
API_KEY=${API_KEY}
WEBHOOK_SECRET=${WEBHOOK_SECRET}
EOF

chmod 600 "${SECRETS_FILE}"
log_success "Secrets saved to ${SECRETS_FILE}"

# Create namespace
log_info "Creating namespace ${NAMESPACE}..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Create secrets in Kubernetes
log_info "Creating Kubernetes secrets..."

kubectl create secret generic postgres-credentials \
  --from-literal=username="${POSTGRES_USER}" \
  --from-literal=password="${POSTGRES_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f - -n "${NAMESPACE}"

kubectl create secret generic redis-credentials \
  --from-literal=password="${REDIS_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f - -n "${NAMESPACE}"

kubectl create secret generic jwt-secrets \
  --from-literal=jwt-secret="${JWT_SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f - -n "${NAMESPACE}"

kubectl create secret generic api-keys \
  --from-literal=catalytic-api-key="${API_KEY}" \
  --from-literal=webhook-signing-secret="${WEBHOOK_SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f - -n "${NAMESPACE}"

log_success "All secrets created in Kubernetes"

# Verify secrets
log_info "Verifying secrets..."
EXPECTED_SECRETS=("postgres-credentials" "redis-credentials" "jwt-secrets" "api-keys")
for secret in "${EXPECTED_SECRETS[@]}"; do
  if kubectl get secret "${secret}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    log_success "✓ ${secret}"
  else
    log_error "✗ ${secret} - MISSING"
    exit 1
  fi
done

# Security audit
log_info "Running security audit..."

# Check .gitignore
if grep -q ".secrets" "$(dirname "${SCRIPT_DIR}")/.gitignore"; then
  log_success "✓ .secrets files are gitignored"
else
  log_warning "⚠ Add .secrets* to .gitignore"
fi

# Check for secrets in Git
if git ls-files --error-unmatch "${SECRETS_FILE}" 2>/dev/null; then
  log_error "✗ Secrets file is tracked by Git!"
  exit 1
else
  log_success "✓ Secrets file not tracked by Git"
fi

log_success "========================================="
log_success "Phase 1 Complete!"
log_success "========================================="
log_info "Secrets file: ${SECRETS_FILE}"
log_info "Next step: Run phase2-images.sh"
