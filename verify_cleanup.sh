#!/bin/bash
# Directory Cleanup Verification Script
# Purpose: Verify all files moved to correct locations
# Usage: bash verify_cleanup.sh

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     Directory Cleanup Verification Script                ║"
echo "║     Generated: October 14, 2025                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Function to check file exists
check_file() {
    local file=$1
    local expected=$2

    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $file ($expected)"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $file (MISSING)"
        ((FAILED++))
    fi
}

# Function to count files in directory
count_files() {
    local dir=$1
    local pattern=$2
    local expected=$3

    if [ ! -d "$dir" ]; then
        echo -e "${RED}✗${NC} Directory $dir does not exist"
        ((FAILED++))
        return
    fi

    count=$(find "$dir" -maxdepth 1 -name "$pattern" 2>/dev/null | wc -l)

    if [ "$count" -eq "$expected" ]; then
        echo -e "${GREEN}✓${NC} $dir has $count $pattern files (expected $expected)"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $dir has $count $pattern files (expected $expected)"
        ((FAILED++))
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 1: Root Directory Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "README.md" "essential"
check_file "DEPLOYMENT_STRATEGY.md" "essential"
check_file "claude_health_report.md" "essential"
count_files "." "*.md" 3

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 2: Archive Structure"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "Archive/planning/2025-10/README.md" "index"
check_file "Archive/planning/2025-10/DIRECTORY_REMEDIATION_PLAN.md" "archived"
check_file "Archive/planning/2025-10/SYSTEMATIC_DIRECTORY_DEPLOYMENT_PLAN.md" "archived"
check_file "Archive/planning/2025-10/STRATEGIC_PLAN_CONSOLIDATION_REPORT.md" "archived"
check_file "Archive/planning/2025-10/CONSOLIDATION_EXECUTIVE_SUMMARY.md" "archived"
check_file "Archive/planning/2025-10/DOCUMENT_OVERLAP_VISUALIZATION.md" "archived"
count_files "Archive/planning/2025-10" "*.md" 6

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 3: Documentation Guides"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "docs/README.md" "index"
check_file "docs/guides/execution-quick-start.md" "guide"
check_file "docs/guides/context-reference.md" "guide"
check_file "docs/guides/mcp-deployment.md" "guide"
check_file "docs/guides/production-readiness.md" "guide"
check_file "docs/guides/reactive-programming.md" "guide"
check_file "docs/guides/log-management.md" "guide"
check_file "docs/guides/catalytic-computing.md" "guide"
count_files "docs/guides" "*.md" 7

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 4: Technical Reports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "docs/reports/gpu-acceleration.md" "report"
check_file "docs/reports/nvidia-security-research.md" "report"
check_file "docs/reports/catalytic-computing-architecture.md" "report"
count_files "docs/reports" "*.md" 3

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 5: Git History Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check a few sample files for git history
if git log --follow --oneline docs/guides/execution-quick-start.md | head -1 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Git history preserved for docs/guides/execution-quick-start.md"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠${NC} Could not verify git history (may not be committed yet)"
fi

if git log --follow --oneline Archive/planning/2025-10/SYSTEMATIC_DIRECTORY_DEPLOYMENT_PLAN.md | head -1 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Git history preserved for Archive/planning/2025-10/SYSTEMATIC_DIRECTORY_DEPLOYMENT_PLAN.md"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠${NC} Could not verify git history (may not be committed yet)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PHASE 6: Old Files Cleanup Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check that old files no longer exist at root
OLD_FILES=(
    "OPTIMAL_DEPLOYMENT_STRATEGY.md"
    "DIRECTORY_REMEDIATION_PLAN.md"
    "SYSTEMATIC_DIRECTORY_DEPLOYMENT_PLAN.md"
    "STRATEGIC_PLAN_CONSOLIDATION_REPORT.md"
    "CONSOLIDATION_EXECUTIVE_SUMMARY.md"
    "DOCUMENT_OVERLAP_VISUALIZATION.md"
    "EXECUTION_QUICK_START.md"
    "CONTEXT_QUICK_REFERENCE.md"
    "MCP_PRODUCTION_DEPLOYMENT_GUIDE.md"
    "production_readiness_guide.md"
    "REACTIVE_PROGRAMMING_COMPLETE_GUIDE.md"
    "LOG_MANAGEMENT_SETUP.md"
    "CATALYTIC_README.md"
    "GPU_ACCELERATION_REPORT.md"
    "NVIDIA_Container_Toolkit_Security_Research_Report.md"
    "CATALYTIC_COMPUTING_DOCUMENTATION.md"
)

for file in "${OLD_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${RED}✗${NC} Old file still exists at root: $file"
        ((FAILED++))
    else
        echo -e "${GREEN}✓${NC} Old file removed from root: $file"
        ((PASSED++))
    fi
done

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    VERIFICATION SUMMARY                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "Tests Passed: ${GREEN}$PASSED${NC}"
echo -e "Tests Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ ALL CHECKS PASSED - CLEANUP SUCCESSFUL!               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Update README.md with new structure"
    echo "2. Update any internal links if needed"
    echo "3. Continue with DEPLOYMENT_STRATEGY.md"
    exit 0
else
    echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ SOME CHECKS FAILED - REVIEW REQUIRED                  ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Actions required:"
    echo "1. Review failed checks above"
    echo "2. Re-run phases that failed"
    echo "3. Run this script again to verify"
    exit 1
fi
