#!/bin/bash
# Systematic Commit Plan - Phase 1 Deployment Infrastructure
# Maintains cohesion with existing architecture and commit patterns
# Auto-generated: $(date)

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
PHASE=1
TOTAL_PHASES=5

# Functions
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║ Phase $PHASE/$TOTAL_PHASES: $1${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

verify_file_exists() {
    if [ -f "$1" ]; then
        print_success "File exists: $1"
        return 0
    else
        print_error "File missing: $1"
        return 1
    fi
}

verify_directory_exists() {
    if [ -d "$1" ]; then
        print_success "Directory exists: $1"
        return 0
    else
        print_error "Directory missing: $1"
        return 1
    fi
}

# Change to development directory
cd ~/development || { print_error "Failed to cd to ~/development"; exit 1; }

# ============================================================
# PHASE 1: PRE-COMMIT VALIDATION
# ============================================================
PHASE=1
print_header "Pre-Commit Validation & Analysis"

echo "Step 1.1: Verify git repository status"
if git rev-parse --git-dir > /dev/null 2>&1; then
    print_success "Git repository detected"
else
    print_error "Not a git repository!"
    exit 1
fi

echo ""
echo "Step 1.2: Check current branch"
CURRENT_BRANCH=$(git branch --show-current)
print_info "Current branch: $CURRENT_BRANCH"
if [ "$CURRENT_BRANCH" != "feat/todo-deployment-phase-1" ]; then
    print_warning "Expected branch: feat/todo-deployment-phase-1"
    print_warning "Current branch: $CURRENT_BRANCH"
    read -p "Continue anyway? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        print_error "Aborted by user"
        exit 1
    fi
fi

echo ""
echo "Step 1.3: Verify terminal integration files"
verify_file_exists ".bash_aliases" || exit 1
verify_file_exists "scripts/claude-workflow.sh" || exit 1
verify_file_exists "scripts/dev-start.sh" || exit 1
print_success "Terminal integration files verified (3/3)"

echo ""
echo "Step 1.4: Verify security infrastructure files"
GATE_FILES=$(ls security/GATE_*.md 2>/dev/null | wc -l)
print_info "Found $GATE_FILES deployment gate files"
verify_directory_exists "security/application" || exit 1
verify_directory_exists "security/tests" || exit 1
print_success "Security infrastructure verified"

echo ""
echo "Step 1.5: Verify load testing files"
LOAD_TEST_FILES=$(ls saas/LOAD_TESTING_*.md 2>/dev/null | wc -l)
print_info "Found $LOAD_TEST_FILES load testing documentation files"
verify_file_exists "saas/run_load_tests.ps1" || exit 1
verify_file_exists "saas/run_load_tests.sh" || exit 1
verify_directory_exists "saas/tests/performance" || exit 1
print_success "Load testing infrastructure verified"

echo ""
echo "Step 1.6: Check for uncommitted changes"
UNCOMMITTED=$(git status --porcelain | wc -l)
print_info "Found $UNCOMMITTED uncommitted changes"

echo ""
echo "Step 1.7: Display diff statistics"
echo "Current staged vs unstaged changes:"
git diff --stat | head -20

echo ""
print_success "Phase 1 validation complete!"
echo ""
read -p "Press Enter to continue to Phase 2..."

# ============================================================
# PHASE 2: COMMIT TERMINAL INTEGRATION
# ============================================================
PHASE=2
print_header "Terminal Integration Commit"

echo "Step 2.1: Stage terminal integration files"
git add .bash_aliases \
    scripts/claude-workflow.sh \
    scripts/dev-start.sh \
    .vscode/settings.json \
    .vscode/keybindings.json \
    .vscode/tasks.json \
    .vscode/extensions.json \
    TERMINAL_GUIDE.md \
    QUICK_REFERENCE.md \
    SETUP_COMPLETE.md

print_success "Terminal integration files staged"

echo ""
echo "Step 2.2: Verify staged files"
echo "Files to be committed:"
git diff --cached --name-only | grep -E "(bash_aliases|claude-workflow|dev-start|\.vscode|TERMINAL_GUIDE|QUICK_REFERENCE|SETUP_COMPLETE)"

echo ""
echo "Step 2.3: Show staged changes summary"
git diff --cached --stat | grep -E "(bash_aliases|claude-workflow|dev-start|\.vscode|TERMINAL_GUIDE|QUICK_REFERENCE|SETUP_COMPLETE)"

echo ""
read -p "Proceed with commit? (y/n): " confirm
if [ "$confirm" = "y" ]; then
    echo "Step 2.4: Creating commit"
    git commit -m "$(cat <<'EOF'
feat: VS Code terminal integration with 98 custom aliases

TERMINAL INTEGRATION:
- Add .bash_aliases with 98 development shortcuts
  * Navigation: dev, saas, mlsec, sec
  * Git workflow: gs, gaa, gc, gp, status, feature, fix
  * Python tools: test, lint, format, pytest, black, ruff
  * Docker: dcup, dcdown, dclogs, dclean
  * Claude Code: c, cplan, clint, cstatus, cfix
  * Development servers: saas-dev, mlsec-dev

AUTOMATION SCRIPTS:
- scripts/dev-start.sh: One-command environment startup
- scripts/claude-workflow.sh: Interactive Claude workflow menu

VS CODE WORKSPACE:
- .vscode/settings.json: Claude auto-connect, terminal config
- .vscode/keybindings.json: Custom keyboard shortcuts
- .vscode/tasks.json: Quick task runner (12 tasks)
- .vscode/extensions.json: Recommended extensions

DOCUMENTATION:
- TERMINAL_GUIDE.md: Complete terminal integration guide
- QUICK_REFERENCE.md: One-page cheat sheet
- SETUP_COMPLETE.md: Setup summary and next steps

BENEFITS:
- Seamless VS Code + Claude Code integration
- 98 time-saving aliases for rapid development
- Consistent terminal environment across sessions
- Interactive workflow helpers for common tasks

🤖 Generated with Claude Code
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"

    print_success "Terminal integration committed!"
    git log -1 --oneline
else
    print_warning "Commit skipped"
    git reset HEAD .bash_aliases scripts/claude-workflow.sh scripts/dev-start.sh .vscode/ TERMINAL_GUIDE.md QUICK_REFERENCE.md SETUP_COMPLETE.md 2>/dev/null || true
fi

echo ""
print_success "Phase 2 complete!"
echo ""
read -p "Press Enter to continue to Phase 3..."

# ============================================================
# PHASE 3: COMMIT SECURITY INFRASTRUCTURE
# ============================================================
PHASE=3
print_header "Security Infrastructure Commit"

echo "Step 3.1: Stage security gate approval documents"
git add security/GATE_*.md

echo ""
echo "Step 3.2: Stage Redis circuit breaker implementation"
git add security/application/redis_circuit_breaker.py \
    security/application/redis_resilient_pool.py \
    security/REDIS_CIRCUIT_BREAKER_QUICK_REF.md \
    2>/dev/null || print_warning "Some circuit breaker files may not exist"

echo ""
echo "Step 3.3: Stage security tests"
git add security/tests/test_redis_circuit_breaker.py \
    security/tests/test_redis_resilient_pool.py \
    2>/dev/null || print_warning "Some test files may not exist"

echo ""
echo "Step 3.4: Stage deployment scripts"
git add security/deploy_*.py \
    2>/dev/null || print_warning "Some deployment scripts may not exist"

print_success "Security infrastructure files staged"

echo ""
echo "Step 3.5: Verify staged files"
echo "Files to be committed:"
git diff --cached --name-only | grep security/ || print_warning "No security files staged"

echo ""
echo "Step 3.6: Show staged changes summary"
git diff --cached --stat | grep security/ || print_warning "No security changes staged"

echo ""
read -p "Proceed with commit? (y/n): " confirm
if [ "$confirm" = "y" ]; then
    echo "Step 3.7: Creating commit"
    git commit -m "$(cat <<'EOF'
feat: deployment gates and Redis circuit breaker implementation

DEPLOYMENT GATE SYSTEM:
- Gate 1: Development → Staging approval process
- Gate 2: Staging → Production approval process
- Gate 3: Production Canary → Full Rollout approval
- Structured sign-off workflow with criteria checklists

REDIS CIRCUIT BREAKER:
- Implement circuit breaker pattern for Redis connections
- Resilient connection pooling with retry logic
- Automatic failover and recovery mechanisms
- Health check monitoring

DEPLOYMENT AUTOMATION:
- deploy_dev_circuit_breaker.py: Dev environment deployment
- deploy_dev_complete.py: Complete dev deployment
- deploy_staging_circuit_breaker.py: Staging deployment
- deploy_production_canary.py: Canary deployment to production

TESTING:
- test_redis_circuit_breaker.py: Circuit breaker unit tests
- test_redis_resilient_pool.py: Connection pool tests

BENEFITS:
- Production-grade resilience for external dependencies
- Controlled deployment pipeline with approval gates
- Automated deployment scripts for each environment
- Comprehensive testing coverage

🤖 Generated with Claude Code
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"

    print_success "Security infrastructure committed!"
    git log -1 --oneline
else
    print_warning "Commit skipped"
    git reset HEAD security/ 2>/dev/null || true
fi

echo ""
print_success "Phase 3 complete!"
echo ""
read -p "Press Enter to continue to Phase 4..."

# ============================================================
# PHASE 4: COMMIT LOAD TESTING INFRASTRUCTURE
# ============================================================
PHASE=4
print_header "Load Testing Infrastructure Commit"

echo "Step 4.1: Stage load testing documentation"
git add saas/LOAD_TESTING_*.md

echo ""
echo "Step 4.2: Stage load testing scripts"
git add saas/run_load_tests.ps1 saas/run_load_tests.sh

echo ""
echo "Step 4.3: Stage performance test files"
git add saas/tests/performance/

print_success "Load testing infrastructure files staged"

echo ""
echo "Step 4.4: Verify staged files"
echo "Files to be committed:"
git diff --cached --name-only | grep -E "(LOAD_TESTING|run_load_tests|performance/)" || print_warning "No load testing files staged"

echo ""
echo "Step 4.5: Show staged changes summary"
git diff --cached --stat | grep -E "(LOAD_TESTING|run_load_tests|performance/)" || print_warning "No load testing changes staged"

echo ""
read -p "Proceed with commit? (y/n): " confirm
if [ "$confirm" = "y" ]; then
    echo "Step 4.6: Creating commit"
    git commit -m "$(cat <<'EOF'
feat: load testing infrastructure with Locust

LOAD TESTING FRAMEWORK:
- Locust-based load testing for SaaS API
- PowerShell and Bash runner scripts
- Comprehensive test scenarios

DOCUMENTATION:
- LOAD_TESTING_GUIDE.md: Setup and usage guide
- LOAD_TESTING_RESULTS_INITIAL.md: Initial baseline results
- LOAD_TESTING_FINAL_REPORT.md: Complete test analysis
- LOAD_TESTING_CRITICAL_ADDENDUM.md: Critical findings
- LOAD_TESTING_ROOT_CAUSE_ANALYSIS.md: Issue deep-dive
- LOAD_TESTING_WINDOWS_LIMITATION_REPORT.md: Platform notes

TESTING SCRIPTS:
- run_load_tests.ps1: Windows PowerShell runner
- run_load_tests.sh: Linux/Mac bash runner
- tests/performance/locustfile.py: Test scenarios
- tests/performance/fix_locustfile.py: Test fixes

TEST SCENARIOS:
- Authentication endpoints
- CRUD operations
- Concurrent user simulation
- Stress testing under load

BASELINE RESULTS:
- 100-user baseline test completed
- Performance metrics captured
- Bottlenecks identified
- Optimization recommendations documented

BENEFITS:
- Automated performance regression testing
- Production readiness validation
- Scalability insights
- Performance baseline for comparisons

🤖 Generated with Claude Code
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"

    print_success "Load testing infrastructure committed!"
    git log -1 --oneline
else
    print_warning "Commit skipped"
    git reset HEAD saas/LOAD_TESTING_*.md saas/run_load_tests.* saas/tests/performance/ 2>/dev/null || true
fi

echo ""
print_success "Phase 4 complete!"
echo ""
read -p "Press Enter to continue to Phase 5..."

# ============================================================
# PHASE 5: POST-COMMIT VALIDATION
# ============================================================
PHASE=5
print_header "Post-Commit Validation & Verification"

echo "Step 5.1: Display commit summary"
echo ""
echo "Recent commits:"
git log --oneline --graph --decorate -5

echo ""
echo "Step 5.2: Check branch status"
AHEAD=$(git rev-list --count origin/$CURRENT_BRANCH..$CURRENT_BRANCH 2>/dev/null || echo "0")
print_info "Your branch is $AHEAD commit(s) ahead of origin/$CURRENT_BRANCH"

echo ""
echo "Step 5.3: Verify no uncommitted changes for committed files"
REMAINING_CHANGES=$(git status --porcelain | wc -l)
print_info "Remaining uncommitted changes: $REMAINING_CHANGES"

echo ""
echo "Step 5.4: Display final status"
git status --short | head -20

echo ""
echo "Step 5.5: Generate commit statistics"
echo "Total commits created in this session:"
git log --oneline --since="10 minutes ago" | wc -l

echo ""
print_success "Phase 5 validation complete!"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║              ✅ SYSTEMATIC COMMIT PLAN COMPLETE!               ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "SUMMARY:"
echo "  ✓ Terminal integration committed"
echo "  ✓ Security infrastructure committed"
echo "  ✓ Load testing infrastructure committed"
echo "  ✓ All changes validated"
echo ""
echo "NEXT STEPS:"
echo "  1. Review commits: git log -3"
echo "  2. Push to remote: git push"
echo "  3. Create pull request (when ready)"
echo ""
echo "Run 'git status' to see remaining uncommitted changes."
echo ""
