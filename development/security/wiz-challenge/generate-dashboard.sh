#!/bin/bash
# generate-dashboard.sh - Visual progress dashboard
# Wiz Zero Day Cloud 2025 Competition

RESEARCH_DIR="$HOME/nvidia-toolkit-research"
CHECKPOINT_DIR="$RESEARCH_DIR/checkpoints"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Count checkpoints
TOTAL_CHECKPOINTS=20
COMPLETED=$(ls "$CHECKPOINT_DIR"/*.done 2>/dev/null | wc -l)
PERCENT=$((COMPLETED * 100 / TOTAL_CHECKPOINTS))
BARS=$((PERCENT / 10))

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   NVIDIA Container Toolkit Security Research Lab              ║"
echo "║   Week 1 Progress Dashboard                                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Overall Progress: [$COMPLETED/$TOTAL_CHECKPOINTS checkpoints]"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Progress bar
printf "["
for i in $(seq 1 10); do
    if [ $i -le $BARS ]; then
        printf "█"
    else
        printf "░"
    fi
done
printf "] $PERCENT%%\n"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Environment Setup Section
echo "🔧 Environment Setup:"
[ -f "$CHECKPOINT_DIR"/01-system-check.done ] && echo "  ✓ Ubuntu 24.04 WSL2" || echo "  ⚠ Ubuntu 24.04 WSL2"
[ -f "$CHECKPOINT_DIR"/04-docker-installed.done ] && echo "  ✓ Docker installed" || echo "  ⚠ Docker installed"
[ -f "$CHECKPOINT_DIR"/06-nvidia-toolkit-installed.done ] && echo "  ✓ NVIDIA Toolkit installed" || echo "  ⚠ NVIDIA Toolkit installed"
[ -f "$CHECKPOINT_DIR"/08-gpu-container-test.done ] && echo "  ✓ GPU container working" || echo "  ⚠ GPU container working"
echo ""

# Security Monitoring Section
echo "🛡️  Security Monitoring:"
[ -f "$CHECKPOINT_DIR"/09-falco-installed.done ] && echo "  ✓ Falco runtime security" || echo "  ⚠ Falco runtime security"
[ -f "$CHECKPOINT_DIR"/10-falco-running.done ] && echo "  ✓ Falco service running" || echo "  ⚠ Falco service running"
[ -f "$CHECKPOINT_DIR"/detection-rules-loaded.done ] && echo "  ✓ Detection rules deployed" || echo "  ⚠ Detection rules deployed"
[ -f "$CHECKPOINT_DIR"/ldpreload-detection-working.done ] && echo "  ✓ Detection tested" || echo "  ⚠ Detection tested"
echo ""

# Security Baseline Section
echo "📊 Security Baseline:"
[ -f "$CHECKPOINT_DIR"/docker-bench-complete.done ] && echo "  ✓ Docker Bench audit" || echo "  ⚠ Docker Bench audit"
[ -f "$CHECKPOINT_DIR"/cve-2024-0132-mitigated.done ] && echo "  ✓ CVE-2024-0132 check" || echo "  ⚠ CVE-2024-0132 check"
[ -f "$CHECKPOINT_DIR"/07-toolkit-version-check.done ] && echo "  ✓ Toolkit version verified" || echo "  ⚠ Toolkit version verified"
echo ""

# Detection Effectiveness
echo "🎯 Detection Effectiveness:"
[ -f "$CHECKPOINT_DIR"/low-false-positive-rate.done ] && echo "  ✓ Low false positive rate" || echo "  ⚠ False positive analysis"
[ -f "$RESEARCH_DIR"/metrics/detection-metrics.txt ] && echo "  ✓ Metrics calculated" || echo "  ⚠ Metrics calculation"
echo ""

# Test Results
if [ -f "$RESEARCH_DIR/tests/test-results.txt" ]; then
    TESTS_PASSED=$(grep -c "PASS" "$RESEARCH_DIR/tests/test-results.txt" || echo "0")
    TESTS_FAILED=$(grep -c "FAIL" "$RESEARCH_DIR/tests/test-results.txt" || echo "0")
    echo "🧪 Test Results:"
    echo "  Passed: $TESTS_PASSED"
    echo "  Failed: $TESTS_FAILED"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next Actions:"
if [ $COMPLETED -lt 10 ]; then
    echo "  → Complete environment setup"
    echo "  → Deploy security monitoring"
elif [ $COMPLETED -lt 15 ]; then
    echo "  → Run security baseline audit"
    echo "  → Test detection effectiveness"
else
    echo "  ✓ Week 1 complete - Ready for Week 2!"
    echo "  → Begin vulnerability research"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Last Updated: $(date)"
echo "Location: $RESEARCH_DIR/"
