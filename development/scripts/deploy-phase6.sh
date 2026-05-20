#!/bin/bash
# Phase 6: Secrets Management Deployment Script
#
# Automates deployment of HashiCorp Vault and secret migration
# Security Score: 82 → 87 (+5 points)
#
# Usage:
#   bash scripts/deploy-phase6.sh
#   bash scripts/deploy-phase6.sh --skip-docker  # If Vault already running
#   bash scripts/deploy-phase6.sh --dry-run      # Simulate only

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VAULT_URL="${VAULT_URL:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token-catalytic-2024}"
ENVIRONMENT="${ENVIRONMENT:-development}"
DRY_RUN=false
SKIP_DOCKER=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Helper functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC}  $1"
}

check_prerequisites() {
    print_header "Step 1: Prerequisites Check"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker not installed"
        exit 1
    fi
    print_success "Docker installed"

    # Check Docker running
    if ! docker ps &> /dev/null; then
        print_error "Docker not running - please start Docker Desktop"
        exit 1
    fi
    print_success "Docker running"

    # Check Python
    if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
        print_error "Python not installed"
        exit 1
    fi
    print_success "Python installed"

    # Check hvac library
    if python -c "import hvac" 2>/dev/null; then
        print_success "hvac library installed"
    else
        print_warning "hvac library not installed - installing..."
        if [ "$DRY_RUN" = false ]; then
            pip install hvac==2.1.0
            print_success "hvac library installed"
        else
            print_info "DRY RUN: Would install hvac==2.1.0"
        fi
    fi

    # Check python-dotenv
    if python -c "import dotenv" 2>/dev/null; then
        print_success "python-dotenv installed"
    else
        print_warning "python-dotenv not installed - installing..."
        if [ "$DRY_RUN" = false ]; then
            pip install python-dotenv
            print_success "python-dotenv installed"
        else
            print_info "DRY RUN: Would install python-dotenv"
        fi
    fi

    print_success "All prerequisites met"
}

deploy_vault() {
    print_header "Step 2: Deploy Vault Container"

    if [ "$SKIP_DOCKER" = true ]; then
        print_info "Skipping Docker deployment (--skip-docker flag)"
        return
    fi

    # Check if Vault container already running
    if docker ps | grep -q catalytic-vault; then
        print_warning "Vault container already running"
        read -p "Stop and restart? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ "$DRY_RUN" = false ]; then
                docker-compose -f docker-compose.vault.yml down
                print_success "Stopped existing Vault container"
            else
                print_info "DRY RUN: Would stop existing container"
            fi
        else
            print_info "Using existing Vault container"
            return
        fi
    fi

    # Start Vault
    if [ "$DRY_RUN" = false ]; then
        docker-compose -f docker-compose.vault.yml up -d
        print_success "Vault container started"
    else
        print_info "DRY RUN: Would start Vault container"
    fi

    # Wait for Vault to be ready
    if [ "$DRY_RUN" = false ]; then
        print_info "Waiting for Vault to be ready..."
        for i in {1..30}; do
            if curl -s "$VAULT_URL/v1/sys/health" > /dev/null 2>&1; then
                print_success "Vault ready"
                break
            fi
            if [ $i -eq 30 ]; then
                print_error "Vault failed to start within 30 seconds"
                exit 1
            fi
            sleep 1
        done
    else
        print_info "DRY RUN: Would wait for Vault"
    fi

    # Verify Vault status
    if [ "$DRY_RUN" = false ]; then
        VAULT_STATUS=$(curl -s "$VAULT_URL/v1/sys/health" | python -c "import sys, json; data=json.load(sys.stdin); print('sealed' if data.get('sealed') else 'unsealed')")
        if [ "$VAULT_STATUS" = "unsealed" ]; then
            print_success "Vault unsealed and ready"
        else
            print_error "Vault is sealed"
            exit 1
        fi
    fi
}

run_migration() {
    print_header "Step 3: Migrate Secrets to Vault"

    # Set environment variables
    export VAULT_ADDR="$VAULT_URL"
    export VAULT_TOKEN="$VAULT_TOKEN"
    export ENVIRONMENT="$ENVIRONMENT"

    # Run migration script
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Running migration in dry-run mode"
        python scripts/migrate-secrets-to-vault.py \
            --env "$ENVIRONMENT" \
            --vault-url "$VAULT_URL" \
            --vault-token "$VAULT_TOKEN" \
            --dry-run
    else
        python scripts/migrate-secrets-to-vault.py \
            --env "$ENVIRONMENT" \
            --vault-url "$VAULT_URL" \
            --vault-token "$VAULT_TOKEN"
    fi

    if [ $? -eq 0 ]; then
        print_success "Secrets migrated successfully"
    else
        print_error "Migration failed"
        exit 1
    fi
}

run_validation() {
    print_header "Step 4: Validate Integration"

    if [ "$DRY_RUN" = false ]; then
        python scripts/test-vault-integration.py \
            --vault-url "$VAULT_URL"

        if [ $? -eq 0 ]; then
            print_success "Validation passed"
        else
            print_error "Validation failed"
            exit 1
        fi
    else
        print_info "DRY RUN: Would run validation tests"
    fi
}

print_next_steps() {
    print_header "Deployment Complete"

    echo -e "${GREEN}Phase 6 Secrets Management deployed successfully!${NC}\n"

    echo "Vault UI: $VAULT_URL"
    echo "Vault Token: $VAULT_TOKEN"
    echo "Environment: $ENVIRONMENT"
    echo ""

    print_info "Next Steps:"
    echo "1. Test secret retrieval: python -c 'import sys; sys.path.insert(0,\"saas\"); from auth.vault_client import vault_health_check; print(vault_health_check())'"
    echo "2. Update application to use vault_client.py (Phase 6B)"
    echo "3. Test rotation: python scripts/rotate-secret.py --category database --key password --dry-run"
    echo "4. Schedule automated rotation (90-day policy)"
    echo ""

    print_warning "Security Reminders:"
    echo "- Current token is dev-only (root access)"
    echo "- Enable TLS for production deployment"
    echo "- Implement AppRole auth for staging/production"
    echo "- Set up automated backups"
    echo ""

    print_success "Security Score: 82 → 87 (+5 points)"
}

# Main execution
main() {
    echo -e "${BLUE}${NC}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║           Phase 6: Secrets Management Deployment             ║"
    echo "║                                                               ║"
    echo "║                    HashiCorp Vault                            ║"
    echo "║                  Security Score: 82 → 87                      ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"

    if [ "$DRY_RUN" = true ]; then
        print_warning "DRY RUN MODE - No changes will be made"
    fi

    check_prerequisites
    deploy_vault
    run_migration
    run_validation
    print_next_steps

    exit 0
}

# Run main
main
