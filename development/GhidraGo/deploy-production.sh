#!/usr/bin/env bash
# GhidraGo v2.0.0 Production Deployment Script
# Security-hardened Go binary analysis toolkit
#
# Usage: ./deploy-production.sh [ghidra_scripts_dir]
# Example: ./deploy-production.sh ~/.ghidra/.ghidra_11.0_PUBLIC/Extensions

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "==============================================="
echo "GhidraGo v2.0.0 Production Deployment"
echo "Security-Hardened Exception Handling"
echo "==============================================="
echo ""

# Determine deployment directory
if [ $# -eq 1 ]; then
    DEPLOY_DIR="$1"
else
    # Default Ghidra user scripts directory
    GHIDRA_USER_DIR="${HOME}/.ghidra"
    # Find latest Ghidra version
    LATEST_GHIDRA=$(find "${GHIDRA_USER_DIR}" -maxdepth 1 -type d -name ".ghidra_*" | sort -V | tail -1)

    if [ -z "${LATEST_GHIDRA}" ]; then
        echo -e "${RED}[!] Could not find Ghidra installation${NC}"
        echo "Usage: $0 [ghidra_scripts_dir]"
        exit 1
    fi

    DEPLOY_DIR="${LATEST_GHIDRA}/ghidra_scripts"
fi

echo "[*] Deployment target: ${DEPLOY_DIR}"

# Verify deployment directory exists
if [ ! -d "${DEPLOY_DIR}" ]; then
    echo -e "${RED}[!] Deployment directory does not exist: ${DEPLOY_DIR}${NC}"
    exit 1
fi

# Verify we're in the correct directory
if [ ! -f "ghidra_scripts/RecoverGoFunctions.py" ]; then
    echo -e "${RED}[!] Must run from GhidraGo root directory${NC}"
    exit 1
fi

echo ""
echo "=== Pre-Deployment Checks ==="

# Run lint checks
echo "[*] Running lint checks..."
if command -v ruff &> /dev/null; then
    if ruff check --select=E722 ghidra_scripts/; then
        echo -e "${GREEN}[✓] Exception handling: PASS${NC}"
    else
        echo -e "${RED}[✗] Exception handling: FAIL${NC}"
        echo "Run: ruff check --select=E722 ghidra_scripts/"
        exit 1
    fi

    if ruff check ghidra_scripts/; then
        echo -e "${GREEN}[✓] Lint checks: PASS${NC}"
    else
        echo -e "${YELLOW}[!] Non-critical lint warnings present${NC}"
    fi
else
    echo -e "${YELLOW}[!] ruff not found - skipping lint checks${NC}"
fi

# Check for required files
echo "[*] Verifying required files..."
REQUIRED_FILES=(
    "ghidra_scripts/RecoverGoFunctions.py"
    "ghidra_scripts/RecoverGoFunctionsAndTypes.py"
    "ghidra_scripts/ghidrago/__init__.py"
    "ghidra_scripts/ghidrago/exceptions.py"
    "ghidra_scripts/ghidrago/moduledata_scanner.py"
    "ghidra_scripts/ghidrago/type_resolver.py"
    "SECURITY_EXCEPTION_HANDLING.md"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}[✗] Missing required file: $file${NC}"
        exit 1
    fi
done
echo -e "${GREEN}[✓] All required files present${NC}"

echo ""
echo "=== Deploying GhidraGo ==="

# Create backup of existing installation if present
if [ -d "${DEPLOY_DIR}/ghidrago" ]; then
    BACKUP_DIR="${DEPLOY_DIR}/ghidrago.backup.$(date +%Y%m%d_%H%M%S)"
    echo "[*] Backing up existing installation to: ${BACKUP_DIR}"
    mv "${DEPLOY_DIR}/ghidrago" "${BACKUP_DIR}"
fi

# Deploy ghidrago module
echo "[*] Deploying ghidrago module..."
cp -r ghidra_scripts/ghidrago "${DEPLOY_DIR}/"
echo -e "${GREEN}[✓] Module deployed${NC}"

# Deploy main scripts
echo "[*] Deploying main scripts..."
cp ghidra_scripts/RecoverGoFunctions.py "${DEPLOY_DIR}/"
cp ghidra_scripts/RecoverGoFunctionsAndTypes.py "${DEPLOY_DIR}/"
echo -e "${GREEN}[✓] Scripts deployed${NC}"

# Deploy documentation
echo "[*] Deploying documentation..."
cp SECURITY_EXCEPTION_HANDLING.md "${DEPLOY_DIR}/ghidrago/"
if [ -f "README.md" ]; then
    cp README.md "${DEPLOY_DIR}/ghidrago/"
fi
echo -e "${GREEN}[✓] Documentation deployed${NC}"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo -e "${GREEN}GhidraGo v2.0.0 successfully deployed to:${NC}"
echo "  ${DEPLOY_DIR}"
echo ""
echo "Available scripts in Ghidra:"
echo "  - Analysis > Golang > Recover Functions"
echo "  - Analysis > Golang > Recover Functions and Types"
echo ""
echo "Security Features:"
echo "  ✓ Production-grade exception handling"
echo "  ✓ KeyboardInterrupt preservation"
echo "  ✓ Detailed error logging"
echo "  ✓ D3FEND-compliant defensive practices"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Restart Ghidra to load new scripts"
echo "  2. Test with a known Go binary"
echo "  3. Review logs for any unexpected errors"
echo ""
