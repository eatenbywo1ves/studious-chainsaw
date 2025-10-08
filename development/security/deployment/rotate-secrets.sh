#!/usr/bin/env bash
# Secret Rotation Script
# D3FEND D3-KM Compliance - Automated Secret Rotation
#
# Usage: ./rotate-secrets.sh [environment]
# Example: ./rotate-secrets.sh development
#
# This script rotates all security-critical secrets:
# - SESSION_SECRET_KEY
# - CSRF_SECRET_KEY
# - REDIS_PASSWORD

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-development}"
ENV_FILE="security/.env.${ENVIRONMENT}"
BACKUP_DIR="security/deployment/backups/secrets"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}Secret Rotation - D3FEND D3-KM Compliance${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo -e "${YELLOW}Environment:${NC} ${ENVIRONMENT}"
echo -e "${YELLOW}Target File:${NC} ${ENV_FILE}"
echo ""

# Verify environment file exists
if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${RED}[!] Environment file not found: ${ENV_FILE}${NC}"
    echo "Available environments:"
    ls -1 security/.env.* 2>/dev/null | sed 's/security\/.env\./  - /' || echo "  (none)"
    exit 1
fi

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Backup current secrets
BACKUP_FILE="${BACKUP_DIR}/.env.${ENVIRONMENT}.backup.$(date +%Y%m%d_%H%M%S)"
echo -e "${BLUE}[*] Creating backup: ${BACKUP_FILE}${NC}"
cp "${ENV_FILE}" "${BACKUP_FILE}"
echo -e "${GREEN}[✓] Backup created${NC}"
echo ""

# Function to generate secure random hex string
generate_hex_secret() {
    local length=$1
    openssl rand -hex "${length}"
}

# Function to generate secure random base64 string
generate_base64_secret() {
    local bytes=$1
    openssl rand -base64 "${bytes}" | tr -d '\n'
}

echo -e "${BLUE}=== Rotating Secrets ===${NC}"
echo ""

# 1. Rotate SESSION_SECRET_KEY
echo -e "${BLUE}[1/3] Rotating SESSION_SECRET_KEY...${NC}"
OLD_SESSION_KEY=$(grep "^SESSION_SECRET_KEY=" "${ENV_FILE}" | cut -d'=' -f2)
NEW_SESSION_KEY=$(generate_hex_secret 32)  # 32 bytes = 64 hex chars

if [ -n "${OLD_SESSION_KEY}" ]; then
    echo -e "  ${YELLOW}Old:${NC} ${OLD_SESSION_KEY:0:16}...${OLD_SESSION_KEY: -16}"
    echo -e "  ${GREEN}New:${NC} ${NEW_SESSION_KEY:0:16}...${NEW_SESSION_KEY: -16}"

    # Update in file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/^SESSION_SECRET_KEY=.*/SESSION_SECRET_KEY=${NEW_SESSION_KEY}/" "${ENV_FILE}"
    else
        # Linux/Git Bash
        sed -i "s/^SESSION_SECRET_KEY=.*/SESSION_SECRET_KEY=${NEW_SESSION_KEY}/" "${ENV_FILE}"
    fi
    echo -e "${GREEN}[✓] SESSION_SECRET_KEY rotated${NC}"
else
    echo -e "${YELLOW}[!] SESSION_SECRET_KEY not found, skipping${NC}"
fi
echo ""

# 2. Rotate CSRF_SECRET_KEY
echo -e "${BLUE}[2/3] Rotating CSRF_SECRET_KEY...${NC}"
OLD_CSRF_KEY=$(grep "^CSRF_SECRET_KEY=" "${ENV_FILE}" | cut -d'=' -f2)
NEW_CSRF_KEY=$(generate_hex_secret 32)  # 32 bytes = 64 hex chars

if [ -n "${OLD_CSRF_KEY}" ]; then
    echo -e "  ${YELLOW}Old:${NC} ${OLD_CSRF_KEY:0:16}...${OLD_CSRF_KEY: -16}"
    echo -e "  ${GREEN}New:${NC} ${NEW_CSRF_KEY:0:16}...${NEW_CSRF_KEY: -16}"

    # Update in file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/^CSRF_SECRET_KEY=.*/CSRF_SECRET_KEY=${NEW_CSRF_KEY}/" "${ENV_FILE}"
    else
        sed -i "s/^CSRF_SECRET_KEY=.*/CSRF_SECRET_KEY=${NEW_CSRF_KEY}/" "${ENV_FILE}"
    fi
    echo -e "${GREEN}[✓] CSRF_SECRET_KEY rotated${NC}"
else
    echo -e "${YELLOW}[!] CSRF_SECRET_KEY not found, skipping${NC}"
fi
echo ""

# 3. Rotate REDIS_PASSWORD
echo -e "${BLUE}[3/3] Rotating REDIS_PASSWORD...${NC}"
OLD_REDIS_PASSWORD=$(grep "^REDIS_PASSWORD=" "${ENV_FILE}" | cut -d'=' -f2)
NEW_REDIS_PASSWORD=$(generate_base64_secret 32)  # 32 bytes base64 encoded

if [ -n "${OLD_REDIS_PASSWORD}" ]; then
    echo -e "  ${YELLOW}Old:${NC} ${OLD_REDIS_PASSWORD:0:16}...${OLD_REDIS_PASSWORD: -8}"
    echo -e "  ${GREEN}New:${NC} ${NEW_REDIS_PASSWORD:0:16}...${NEW_REDIS_PASSWORD: -8}"

    # Update REDIS_PASSWORD
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${NEW_REDIS_PASSWORD}|" "${ENV_FILE}"
        # Also update REDIS_URL
        sed -i '' "s|^REDIS_URL=redis://:[^@]*@|REDIS_URL=redis://:${NEW_REDIS_PASSWORD}@|" "${ENV_FILE}"
    else
        sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${NEW_REDIS_PASSWORD}|" "${ENV_FILE}"
        # Also update REDIS_URL
        sed -i "s|^REDIS_URL=redis://:[^@]*@|REDIS_URL=redis://:${NEW_REDIS_PASSWORD}@|" "${ENV_FILE}"
    fi
    echo -e "${GREEN}[✓] REDIS_PASSWORD rotated (URL updated)${NC}"
else
    echo -e "${YELLOW}[!] REDIS_PASSWORD not found, skipping${NC}"
fi
echo ""

echo -e "${BLUE}=== Rotation Summary ===${NC}"
echo ""
echo -e "${GREEN}[✓] All secrets rotated successfully${NC}"
echo -e "${YELLOW}[!] Backup saved to: ${BACKUP_FILE}${NC}"
echo ""

# Verify rotation
echo -e "${BLUE}=== Verification ===${NC}"
echo ""
CURRENT_SESSION=$(grep "^SESSION_SECRET_KEY=" "${ENV_FILE}" | cut -d'=' -f2)
CURRENT_CSRF=$(grep "^CSRF_SECRET_KEY=" "${ENV_FILE}" | cut -d'=' -f2)
CURRENT_REDIS=$(grep "^REDIS_PASSWORD=" "${ENV_FILE}" | cut -d'=' -f2)

if [ "${CURRENT_SESSION}" != "${OLD_SESSION_KEY}" ]; then
    echo -e "${GREEN}[✓] SESSION_SECRET_KEY changed${NC}"
else
    echo -e "${RED}[✗] SESSION_SECRET_KEY unchanged${NC}"
fi

if [ "${CURRENT_CSRF}" != "${OLD_CSRF_KEY}" ]; then
    echo -e "${GREEN}[✓] CSRF_SECRET_KEY changed${NC}"
else
    echo -e "${RED}[✗] CSRF_SECRET_KEY unchanged${NC}"
fi

if [ "${CURRENT_REDIS}" != "${OLD_REDIS_PASSWORD}" ]; then
    echo -e "${GREEN}[✓] REDIS_PASSWORD changed${NC}"
else
    echo -e "${RED}[✗] REDIS_PASSWORD unchanged${NC}"
fi

echo ""
echo -e "${YELLOW}=== Important Notes ===${NC}"
echo ""
echo -e "1. ${YELLOW}Restart all services${NC} to apply new secrets"
echo -e "   - Stop all running applications"
echo -e "   - Restart Redis with new password"
echo -e "   - Start applications with new .env file"
echo ""
echo -e "2. ${YELLOW}Update Redis configuration${NC}"
echo -e "   - Edit Redis config: requirepass ${NEW_REDIS_PASSWORD}"
echo -e "   - Or use: redis-cli CONFIG SET requirepass '${NEW_REDIS_PASSWORD}'"
echo ""
echo -e "3. ${YELLOW}Session invalidation${NC}"
echo -e "   - All existing user sessions will be invalidated"
echo -e "   - Users will need to log in again"
echo ""
echo -e "4. ${YELLOW}Backup retention${NC}"
echo -e "   - Keep backup for rollback: ${BACKUP_FILE}"
echo -e "   - Delete after successful deployment"
echo ""
echo -e "${BLUE}Secret rotation complete!${NC}"
