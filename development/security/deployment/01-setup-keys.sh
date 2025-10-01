#!/usr/bin/env bash
#
# Security Setup - RSA Key Generation
# Generates JWT RSA key pairs for secure authentication
#

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${SECURITY_DIR}/keys"
ENV="${1:-development}"

echo -e "${GREEN}=== Security Key Generation ===${NC}"
echo "Environment: ${ENV}"
echo "Keys directory: ${KEYS_DIR}"
echo ""

# Create keys directory if it doesn't exist
if [ ! -d "${KEYS_DIR}" ]; then
    echo -e "${YELLOW}Creating keys directory...${NC}"
    mkdir -p "${KEYS_DIR}"
    chmod 700 "${KEYS_DIR}"
fi

# Generate RSA key pair for JWT
generate_jwt_keys() {
    local key_name="jwt_${ENV}"
    local private_key="${KEYS_DIR}/${key_name}_private.pem"
    local public_key="${KEYS_DIR}/${key_name}_public.pem"

    if [ -f "${private_key}" ]; then
        echo -e "${YELLOW}JWT keys for ${ENV} already exist. Skipping generation.${NC}"
        echo -e "${YELLOW}To regenerate, delete ${private_key} and run again.${NC}"
        return 0
    fi

    echo -e "${GREEN}Generating JWT RSA key pair (2048-bit)...${NC}"

    # Generate private key
    openssl genrsa -out "${private_key}" 2048

    # Generate public key from private key
    openssl rsa -in "${private_key}" -pubout -out "${public_key}"

    # Set proper permissions
    chmod 600 "${private_key}"
    chmod 644 "${public_key}"

    echo -e "${GREEN}✓ JWT keys generated successfully${NC}"
    echo "  Private key: ${private_key}"
    echo "  Public key: ${public_key}"
    echo ""
}

# Generate API encryption keys
generate_api_keys() {
    local key_name="api_encryption_${ENV}"
    local key_file="${KEYS_DIR}/${key_name}.key"

    if [ -f "${key_file}" ]; then
        echo -e "${YELLOW}API encryption key for ${ENV} already exists. Skipping.${NC}"
        return 0
    fi

    echo -e "${GREEN}Generating API encryption key (256-bit)...${NC}"

    # Generate random 256-bit key
    openssl rand -hex 32 > "${key_file}"
    chmod 600 "${key_file}"

    echo -e "${GREEN}✓ API encryption key generated${NC}"
    echo "  Key file: ${key_file}"
    echo ""
}

# Generate database encryption keys
generate_db_keys() {
    local key_name="db_encryption_${ENV}"
    local key_file="${KEYS_DIR}/${key_name}.key"

    if [ -f "${key_file}" ]; then
        echo -e "${YELLOW}Database encryption key for ${ENV} already exists. Skipping.${NC}"
        return 0
    fi

    echo -e "${GREEN}Generating database encryption key (256-bit)...${NC}"

    openssl rand -hex 32 > "${key_file}"
    chmod 600 "${key_file}"

    echo -e "${GREEN}✓ Database encryption key generated${NC}"
    echo "  Key file: ${key_file}"
    echo ""
}

# Generate secrets for Kubernetes
generate_k8s_secrets() {
    local namespace="${2:-catalytic-${ENV}}"

    echo -e "${GREEN}Generating Kubernetes secrets...${NC}"

    local private_key="${KEYS_DIR}/jwt_${ENV}_private.pem"
    local public_key="${KEYS_DIR}/jwt_${ENV}_public.pem"

    if [ ! -f "${private_key}" ] || [ ! -f "${public_key}" ]; then
        echo -e "${RED}Error: JWT keys not found. Run key generation first.${NC}"
        return 1
    fi

    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        echo -e "${YELLOW}kubectl not found. Skipping Kubernetes secret creation.${NC}"
        echo -e "${YELLOW}You can manually create secrets later using:${NC}"
        echo "  kubectl create secret generic catalytic-security-keys \\"
        echo "    --from-file=jwt-private=${private_key} \\"
        echo "    --from-file=jwt-public=${public_key} \\"
        echo "    -n ${namespace}"
        return 0
    fi

    # Check if namespace exists
    if ! kubectl get namespace "${namespace}" &> /dev/null; then
        echo -e "${YELLOW}Creating namespace: ${namespace}${NC}"
        kubectl create namespace "${namespace}"
    fi

    # Delete existing secret if it exists
    kubectl delete secret catalytic-security-keys -n "${namespace}" 2>/dev/null || true

    # Create Kubernetes secret
    kubectl create secret generic catalytic-security-keys \
        --from-file=jwt-private="${private_key}" \
        --from-file=jwt-public="${public_key}" \
        -n "${namespace}"

    echo -e "${GREEN}✓ Kubernetes secret created in namespace: ${namespace}${NC}"
    echo ""
}

# Create .env template
create_env_template() {
    local env_file="${SECURITY_DIR}/.env.${ENV}.template"

    if [ -f "${env_file}" ]; then
        echo -e "${YELLOW}.env template already exists. Skipping.${NC}"
        return 0
    fi

    echo -e "${GREEN}Creating .env template...${NC}"

    cat > "${env_file}" << EOF
# Security Configuration for ${ENV}
# Copy this file to .env.${ENV} and fill in the values

# JWT Configuration
JWT_PRIVATE_KEY_PATH=${KEYS_DIR}/jwt_${ENV}_private.pem
JWT_PUBLIC_KEY_PATH=${KEYS_DIR}/jwt_${ENV}_public.pem
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# API Encryption
API_ENCRYPTION_KEY_PATH=${KEYS_DIR}/api_encryption_${ENV}.key

# Database Encryption
DB_ENCRYPTION_KEY_PATH=${KEYS_DIR}/db_encryption_${ENV}.key

# Security Level (basic, enhanced, strict)
SECURITY_LEVEL=enhanced

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_BURST=10

# DDoS Protection
DDOS_PROTECTION_ENABLED=true
DDOS_BLOCK_DURATION_MINUTES=60

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
CORS_ALLOW_CREDENTIALS=true

# Session Configuration
SESSION_SECRET_KEY=$(openssl rand -hex 32)
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=strict

# CSRF Protection
CSRF_ENABLED=true
CSRF_SECRET_KEY=$(openssl rand -hex 32)
EOF

    chmod 600 "${env_file}"

    echo -e "${GREEN}✓ .env template created${NC}"
    echo "  Template: ${env_file}"
    echo -e "${YELLOW}  Copy to .env.${ENV} and customize as needed${NC}"
    echo ""
}

# Verify key generation
verify_keys() {
    echo -e "${GREEN}Verifying generated keys...${NC}"

    local private_key="${KEYS_DIR}/jwt_${ENV}_private.pem"
    local public_key="${KEYS_DIR}/jwt_${ENV}_public.pem"

    # Verify private key
    if openssl rsa -in "${private_key}" -check -noout 2>/dev/null; then
        echo -e "${GREEN}✓ Private key is valid${NC}"
    else
        echo -e "${RED}✗ Private key is invalid!${NC}"
        return 1
    fi

    # Verify public key
    if openssl rsa -in "${public_key}" -pubin -text -noout > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Public key is valid${NC}"
    else
        echo -e "${RED}✗ Public key is invalid!${NC}"
        return 1
    fi

    # Verify key pair match
    private_modulus=$(openssl rsa -in "${private_key}" -noout -modulus 2>/dev/null | openssl md5)
    public_modulus=$(openssl rsa -in "${public_key}" -pubin -noout -modulus 2>/dev/null | openssl md5)

    if [ "${private_modulus}" == "${public_modulus}" ]; then
        echo -e "${GREEN}✓ Key pair matches${NC}"
    else
        echo -e "${RED}✗ Key pair mismatch!${NC}"
        return 1
    fi

    echo ""
}

# Main execution
main() {
    echo -e "${GREEN}Starting security key generation for environment: ${ENV}${NC}"
    echo ""

    # Generate all keys
    generate_jwt_keys
    generate_api_keys
    generate_db_keys

    # Verify keys
    verify_keys

    # Create environment template
    create_env_template

    # Generate Kubernetes secrets if requested
    if [ "${ENV}" != "development" ]; then
        read -p "Generate Kubernetes secrets for ${ENV}? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            generate_k8s_secrets
        fi
    fi

    echo -e "${GREEN}=== Key Generation Complete ===${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review generated keys in: ${KEYS_DIR}"
    echo "  2. Copy .env.${ENV}.template to .env.${ENV}"
    echo "  3. Customize .env.${ENV} with your configuration"
    echo "  4. Run container build script: ./02-build-containers.sh ${ENV}"
    echo ""
    echo -e "${YELLOW}Important: Keep these keys secure and never commit them to version control!${NC}"
}

# Run main function
main
