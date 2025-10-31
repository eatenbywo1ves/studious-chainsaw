#!/bin/bash
# ============================================================================
# Kubernetes Secret Generation Script
# ============================================================================
# This script generates secure secrets for Kubernetes deployment
# Run this script BEFORE deploying to staging or production
#
# Usage:
#   ./generate-secrets.sh staging   # Generate secrets for staging
#   ./generate-secrets.sh production # Generate secrets for production
# ============================================================================

set -e

ENVIRONMENT=${1:-staging}
NAMESPACE="catalytic-${ENVIRONMENT}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Kubernetes Secret Generation${NC}"
echo -e "${GREEN}Environment: ${ENVIRONMENT}${NC}"
echo -e "${GREEN}Namespace: ${NAMESPACE}${NC}"
echo -e "${GREEN}============================================${NC}"
echo

# Validate environment parameter
if [[ "${ENVIRONMENT}" != "staging" && "${ENVIRONMENT}" != "production" ]]; then
    echo -e "${RED}ERROR: Environment must be 'staging' or 'production'${NC}"
    echo "Usage: $0 [staging|production]"
    exit 1
fi

# Check if namespace exists
if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo -e "${YELLOW}Namespace ${NAMESPACE} does not exist. Creating it...${NC}"
    kubectl create namespace "${NAMESPACE}"
fi

# ============================================================================
# 1. Generate PostgreSQL Credentials
# ============================================================================
echo -e "${YELLOW}1. Generating PostgreSQL credentials...${NC}"

if [[ "${ENVIRONMENT}" == "production" ]]; then
    DB_PASSWORD=$(openssl rand -base64 48)
    DB_USER="catalytic_prod"
else
    DB_PASSWORD=$(openssl rand -base64 32)
    DB_USER="catalytic_staging"
fi

kubectl create secret generic postgres-credentials \
    --from-literal=username="${DB_USER}" \
    --from-literal=password="${DB_PASSWORD}" \
    --namespace="${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}✓ PostgreSQL credentials created${NC}"
echo "  Username: ${DB_USER}"
echo "  Password: (saved to Kubernetes secret)"
echo

# ============================================================================
# 2. Generate Redis Credentials
# ============================================================================
echo -e "${YELLOW}2. Generating Redis credentials...${NC}"

if [[ "${ENVIRONMENT}" == "production" ]]; then
    REDIS_PASSWORD=$(openssl rand -base64 48)
else
    REDIS_PASSWORD=$(openssl rand -base64 32)
fi

kubectl create secret generic redis-credentials \
    --from-literal=password="${REDIS_PASSWORD}" \
    --namespace="${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}✓ Redis credentials created${NC}"
echo "  Password: (saved to Kubernetes secret)"
echo

# ============================================================================
# 3. Generate JWT Secrets
# ============================================================================
echo -e "${YELLOW}3. Generating JWT secrets...${NC}"

# For production, require RSA key pair
if [[ "${ENVIRONMENT}" == "production" ]]; then
    echo "For production, you should use RSA key pairs (RS256 algorithm)."
    echo "Generating RSA key pair..."

    # Create temporary directory for keys
    TEMP_DIR=$(mktemp -d)

    # Generate RSA private key
    openssl genrsa -out "${TEMP_DIR}/jwt-private.pem" 4096

    # Generate RSA public key from private key
    openssl rsa -in "${TEMP_DIR}/jwt-private.pem" -pubout -out "${TEMP_DIR}/jwt-public.pem"

    # Create secret with both keys
    kubectl create secret generic jwt-secrets \
        --from-file=jwt-private-key="${TEMP_DIR}/jwt-private.pem" \
        --from-file=jwt-public-key="${TEMP_DIR}/jwt-public.pem" \
        --namespace="${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -

    # Clean up temporary files
    rm -rf "${TEMP_DIR}"

    echo -e "${GREEN}✓ JWT RSA key pair created${NC}"
else
    # For staging, use simple secret key
    JWT_SECRET=$(openssl rand -hex 32)

    kubectl create secret generic jwt-secrets \
        --from-literal=jwt-secret="${JWT_SECRET}" \
        --namespace="${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo -e "${GREEN}✓ JWT secret created${NC}"
fi
echo

# ============================================================================
# 4. Generate API Keys and Webhook Secrets
# ============================================================================
echo -e "${YELLOW}4. Generating API keys and webhook secrets...${NC}"

if [[ "${ENVIRONMENT}" == "production" ]]; then
    API_KEY=$(openssl rand -hex 48)
    WEBHOOK_SECRET=$(openssl rand -hex 48)
else
    API_KEY=$(openssl rand -hex 32)
    WEBHOOK_SECRET=$(openssl rand -hex 32)
fi

kubectl create secret generic api-keys \
    --from-literal=catalytic-api-key="${API_KEY}" \
    --from-literal=webhook-signing-secret="${WEBHOOK_SECRET}" \
    --namespace="${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}✓ API keys created${NC}"
echo

# ============================================================================
# 5. Generate CSRF Secret
# ============================================================================
echo -e "${YELLOW}5. Generating CSRF secret...${NC}"

if [[ "${ENVIRONMENT}" == "production" ]]; then
    CSRF_SECRET=$(openssl rand -hex 48)
else
    CSRF_SECRET=$(openssl rand -hex 32)
fi

kubectl create secret generic csrf-secret \
    --from-literal=csrf-secret-key="${CSRF_SECRET}" \
    --namespace="${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}✓ CSRF secret created${NC}"
echo

# ============================================================================
# Summary
# ============================================================================
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Secret Generation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo
echo "The following secrets were created in namespace '${NAMESPACE}':"
echo "  1. postgres-credentials"
echo "  2. redis-credentials"
echo "  3. jwt-secrets"
echo "  4. api-keys"
echo "  5. csrf-secret"
echo
echo -e "${YELLOW}IMPORTANT SECURITY NOTES:${NC}"
echo "  - These secrets are stored ONLY in Kubernetes"
echo "  - Backup your secrets using: kubectl get secrets -n ${NAMESPACE} -o yaml > secrets-backup-${ENVIRONMENT}.yaml"
echo "  - Store backups securely (encrypted, in a password manager, or vault)"
echo "  - Consider using external secret management (Vault, AWS Secrets Manager, etc.)"
echo "  - Rotate secrets regularly (every 90 days recommended)"
echo
echo "To view created secrets:"
echo "  kubectl get secrets -n ${NAMESPACE}"
echo
echo "To view a specific secret (base64 decoded):"
echo "  kubectl get secret postgres-credentials -n ${NAMESPACE} -o jsonpath='{.data.password}' | base64 -d"
echo

# ============================================================================
# Optional: Create TLS certificate secret for production
# ============================================================================
if [[ "${ENVIRONMENT}" == "production" ]]; then
    echo -e "${YELLOW}============================================${NC}"
    echo -e "${YELLOW}TLS Certificate Setup${NC}"
    echo -e "${YELLOW}============================================${NC}"
    echo
    echo "For production, you need to create a TLS certificate secret."
    echo
    echo "Option 1: Use cert-manager (recommended):"
    echo "  - Install cert-manager in your cluster"
    echo "  - Configure a ClusterIssuer (Let's Encrypt, etc.)"
    echo "  - Add TLS annotation to your Ingress resource"
    echo
    echo "Option 2: Manual certificate:"
    echo "  kubectl create secret tls catalytic-tls \\"
    echo "    --cert=path/to/tls.crt \\"
    echo "    --key=path/to/tls.key \\"
    echo "    -n ${NAMESPACE}"
    echo
fi

echo -e "${GREEN}Done!${NC}"
