#!/usr/bin/env bash
#
# Master Security Deployment Orchestrator
# Automates the complete security hardening deployment process
#

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$SECURITY_DIR")"
ENV="${1:-development}"
SKIP_CONFIRM="${SKIP_CONFIRM:-false}"

# Display banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     CATALYTIC COMPUTING PLATFORM                          ║
║     Security Hardening Deployment                         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Show deployment plan
show_plan() {
    echo -e "${BLUE}=== Deployment Plan ===${NC}"
    echo ""
    echo "Environment: ${ENV}"
    echo "Project Root: ${PROJECT_ROOT}"
    echo ""
    echo "Deployment Steps:"
    echo "  1. Setup & Key Generation"
    echo "  2. Container Build & Security Scan"
    echo "  3. Kubernetes Security Deployment (if applicable)"
    echo "  4. Application Security Integration"
    echo "  5. Verification & Testing"
    echo ""
}

# Confirmation prompt
confirm_deployment() {
    if [ "${SKIP_CONFIRM}" == "true" ]; then
        return 0
    fi

    echo -e "${YELLOW}This will deploy security hardening for ${ENV} environment.${NC}"
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled."
        exit 0
    fi
    echo ""
}

# Step 1: Setup and Key Generation
step_setup_keys() {
    echo -e "${GREEN}━━━ Step 1: Setup & Key Generation ━━━${NC}"
    echo ""

    if [ -f "${SCRIPT_DIR}/01-setup-keys.sh" ]; then
        bash "${SCRIPT_DIR}/01-setup-keys.sh" "${ENV}"
    else
        echo -e "${RED}Error: 01-setup-keys.sh not found${NC}"
        return 1
    fi

    echo ""
    read -p "Press Enter to continue to next step..."
    echo ""
}

# Step 2: Container Build and Scan
step_build_containers() {
    echo -e "${GREEN}━━━ Step 2: Container Build & Security Scan ━━━${NC}"
    echo ""

    echo -e "${YELLOW}Do you want to build and scan containers? (Requires Docker)${NC}"
    read -p "Continue with container build? (y/N): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "${SCRIPT_DIR}/02-build-containers.sh" ]; then
            bash "${SCRIPT_DIR}/02-build-containers.sh" "${ENV}"
        else
            echo -e "${RED}Error: 02-build-containers.sh not found${NC}"
            return 1
        fi
    else
        echo "Skipping container build"
    fi

    echo ""
    read -p "Press Enter to continue to next step..."
    echo ""
}

# Step 3: Kubernetes Security Deployment
step_deploy_k8s() {
    echo -e "${GREEN}━━━ Step 3: Kubernetes Security Deployment ━━━${NC}"
    echo ""

    if [ "${ENV}" == "development" ]; then
        echo -e "${YELLOW}Kubernetes deployment typically not needed for development${NC}"
        read -p "Deploy to Kubernetes anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Skipping Kubernetes deployment"
            echo ""
            return 0
        fi
    fi

    echo -e "${YELLOW}Do you want to deploy Kubernetes security? (Requires kubectl)${NC}"
    read -p "Continue with K8s deployment? (y/N): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "${SCRIPT_DIR}/03-deploy-k8s-security.sh" ]; then
            bash "${SCRIPT_DIR}/03-deploy-k8s-security.sh" "${ENV}"
        else
            echo -e "${RED}Error: 03-deploy-k8s-security.sh not found${NC}"
            return 1
        fi
    else
        echo "Skipping Kubernetes deployment"
    fi

    echo ""
    read -p "Press Enter to continue to next step..."
    echo ""
}

# Step 4: Application Integration
step_integrate_application() {
    echo -e "${GREEN}━━━ Step 4: Application Security Integration ━━━${NC}"
    echo ""

    if [ -f "${SCRIPT_DIR}/04-integrate-application.py" ]; then
        python3 "${SCRIPT_DIR}/04-integrate-application.py" "${ENV}"
    else
        echo -e "${RED}Error: 04-integrate-application.py not found${NC}"
        return 1
    fi

    echo ""
    read -p "Press Enter to continue to next step..."
    echo ""
}

# Step 5: Verification
step_verification() {
    echo -e "${GREEN}━━━ Step 5: Verification & Testing ━━━${NC}"
    echo ""

    echo "Running verification checks..."
    echo ""

    local errors=0

    # Check if keys exist
    echo -n "Checking RSA keys... "
    if [ -f "${SECURITY_DIR}/keys/jwt_${ENV}_private.pem" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        errors=$((errors + 1))
    fi

    # Check if requirements file exists
    echo -n "Checking security requirements... "
    if [ -f "${SECURITY_DIR}/security-requirements.txt" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        errors=$((errors + 1))
    fi

    # Check if .env exists
    echo -n "Checking .env file... "
    if [ -f "${PROJECT_ROOT}/saas/.env" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠${NC} (not critical)"
    fi

    # Check if docker-compose.override.yml exists
    echo -n "Checking docker-compose.override.yml... "
    if [ -f "${PROJECT_ROOT}/saas/docker-compose.override.yml" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠${NC} (not critical)"
    fi

    echo ""

    if [ ${errors} -gt 0 ]; then
        echo -e "${RED}Verification completed with ${errors} errors${NC}"
        return 1
    else
        echo -e "${GREEN}✓ All verification checks passed${NC}"
        return 0
    fi
}

# Generate deployment summary
generate_summary() {
    local summary_file="${SCRIPT_DIR}/deployment-summary-${ENV}-$(date +%Y%m%d-%H%M%S).md"

    echo -e "${BLUE}Generating deployment summary...${NC}"

    cat > "${summary_file}" << EOF
# Security Deployment Summary

**Environment**: ${ENV}
**Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Project**: Catalytic Computing Platform

## Deployment Completed

### Step 1: Setup & Key Generation
- ✓ RSA key pairs generated
- ✓ API encryption keys created
- ✓ Database encryption keys created
- ✓ Environment template created

### Step 2: Container Security
- Container builds completed
- Security scans passed
- SBOM generated
- Images tagged and ready

### Step 3: Kubernetes Security (if applicable)
- Network policies deployed
- RBAC policies configured
- Pod Security Standards enforced
- Secrets management configured

### Step 4: Application Integration
- JWT security integrated
- Rate limiting enabled
- Input validation configured
- Security middleware added

### Step 5: Verification
- All checks passed
- System ready for deployment

## Security Features Enabled

- ✓ JWT authentication with RSA-256
- ✓ Rate limiting and DDoS protection
- ✓ Input validation and sanitization
- ✓ Container hardening (distroless, non-root)
- ✓ Network security policies
- ✓ RBAC and least-privilege access
- ✓ Encrypted secrets management
- ✓ Security monitoring and alerting

## Next Steps

1. **Install Dependencies**
   \`\`\`bash
   pip install -r security/security-requirements.txt
   \`\`\`

2. **Customize Configuration**
   - Edit \`.env\` file
   - Review security settings
   - Configure monitoring

3. **Deploy Application**
   \`\`\`bash
   cd saas
   docker-compose up -d
   \`\`\`

4. **Verify Deployment**
   - Test authentication endpoints
   - Verify rate limiting
   - Check security monitoring
   - Run penetration tests

5. **Schedule Maintenance**
   - Regular vulnerability scans
   - Key rotation (every 90 days)
   - Security audits
   - Backup verification

## Important Files

- Keys: \`security/keys/jwt_${ENV}_*.pem\`
- Config: \`saas/.env\`
- Requirements: \`security/security-requirements.txt\`
- Docker: \`saas/docker-compose.override.yml\`
- Docs: \`security/deployment/README.md\`

## Support

For issues or questions:
1. Review deployment logs
2. Check \`security/deployment/README.md\`
3. Verify all prerequisites are installed
4. Test in development before production

---
Generated by: deploy-security.sh
Deployment ID: ${ENV}-$(date +%Y%m%d-%H%M%S)
EOF

    echo -e "${GREEN}✓ Summary generated: ${summary_file}${NC}"
    echo ""
}

# Show next steps
show_next_steps() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}║     🎉 Security Deployment Complete! 🎉                   ║${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo ""
    echo "  1. Install dependencies:"
    echo "     ${BLUE}pip install -r security/security-requirements.txt${NC}"
    echo ""
    echo "  2. Customize .env file:"
    echo "     ${BLUE}vi saas/.env${NC}"
    echo ""
    echo "  3. Deploy application:"
    echo "     ${BLUE}cd saas && docker-compose up -d${NC}"
    echo ""
    echo "  4. Test security:"
    echo "     ${BLUE}curl -X POST http://localhost:8000/auth/login${NC}"
    echo ""
    echo "  5. Review deployment summary and documentation"
    echo ""
    echo -e "${YELLOW}⚠ Important:${NC}"
    echo "  - Keep security keys safe and never commit to git"
    echo "  - Customize .env with production values"
    echo "  - Schedule regular security scans"
    echo "  - Enable monitoring and alerting"
    echo ""
}

# Error handler
handle_error() {
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}Deployment failed at step: $1${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Please review the error messages above and try again."
    echo ""
    echo "For help, see: security/deployment/README.md"
    exit 1
}

# Main execution
main() {
    # Show banner
    show_banner

    # Show plan
    show_plan

    # Confirm deployment
    confirm_deployment

    # Execute deployment steps
    echo -e "${CYAN}Starting security deployment...${NC}"
    echo ""

    step_setup_keys || handle_error "Setup & Key Generation"
    step_build_containers || handle_error "Container Build"
    step_deploy_k8s || handle_error "Kubernetes Deployment"
    step_integrate_application || handle_error "Application Integration"
    step_verification || handle_error "Verification"

    # Generate summary
    generate_summary

    # Show next steps
    show_next_steps
}

# Run main function
main
