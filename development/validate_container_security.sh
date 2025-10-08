#!/bin/bash

# Container Security Validation Suite
# Wiz ZeroDay.Cloud 2025 - Defensive Testing
# Tests container escape prevention measures

set -e

CONTAINER_NAME="ghidra-ml-similarity"
GPU_EXPORTER="ghidra-ml-gpu-exporter"
CADVISOR="ghidra-ml-cadvisor"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║   Container Security Validation Suite - Wiz ZeroDay.Cloud 2025  ║"
echo "║              Defensive Testing Framework                         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

test_result() {
    local test_name=$1
    local result=$2
    local details=$3

    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $test_name"
        [ -n "$details" ] && echo "   └─ $details"
        ((PASS_COUNT++))
    elif [ "$result" = "FAIL" ]; then
        echo -e "${RED}❌ FAIL${NC}: $test_name"
        [ -n "$details" ] && echo "   └─ $details"
        ((FAIL_COUNT++))
    else
        echo -e "${YELLOW}⚠️  WARN${NC}: $test_name"
        [ -n "$details" ] && echo "   └─ $details"
        ((WARN_COUNT++))
    fi
}

# Test 1: Container Escape Prevention
echo -e "\n${BLUE}[Test 1] Container Escape Prevention${NC}"
echo "───────────────────────────────────────"

# Test 1.1: Host filesystem access
if docker exec $CONTAINER_NAME bash -c "ls /host" 2>&1 | grep -q "No such file"; then
    test_result "Host filesystem isolation" "PASS" "Container cannot access /host"
else
    test_result "Host filesystem isolation" "FAIL" "Container can access /host"
fi

# Test 1.2: Host root access via /proc/1/root
if docker exec $CONTAINER_NAME bash -c "cat /proc/1/root/etc/hostname" 2>&1 | grep -q "Permission denied\|No such file"; then
    test_result "Host root access prevention" "PASS" "Cannot access host root via /proc/1/root"
else
    test_result "Host root access prevention" "FAIL" "Can access host root"
fi

# Test 1.3: Kernel module loading
if docker exec $CONTAINER_NAME bash -c "lsmod" 2>&1 | grep -q "Permission denied\|command not found"; then
    test_result "Kernel module enumeration blocked" "PASS" "Cannot enumerate kernel modules"
else
    test_result "Kernel module enumeration blocked" "WARN" "Can enumerate kernel modules (info disclosure)"
fi

# Test 2: Capability Validation
echo -e "\n${BLUE}[Test 2] Linux Capabilities Validation${NC}"
echo "───────────────────────────────────────"

# Test 2.1: Check effective capabilities
CAPS=$(docker exec $CONTAINER_NAME bash -c "grep CapEff /proc/self/status | awk '{print \$2}'")
if [ "$CAPS" = "0000000000000400" ] || [ "$CAPS" = "0000000000000000" ]; then
    test_result "Minimal capabilities enforced" "PASS" "Only NET_BIND_SERVICE or none"
else
    test_result "Minimal capabilities enforced" "WARN" "Capabilities: $CAPS"
fi

# Test 2.2: SYS_ADMIN check (should NOT be present)
if docker exec $CONTAINER_NAME bash -c "capsh --print 2>/dev/null" | grep -q "cap_sys_admin"; then
    test_result "CAP_SYS_ADMIN absence" "FAIL" "CAP_SYS_ADMIN is present (CRITICAL)"
else
    test_result "CAP_SYS_ADMIN absence" "PASS" "CAP_SYS_ADMIN not present"
fi

# Test 2.3: Check GPU exporter capabilities (CRITICAL)
echo -e "\n${YELLOW}Checking GPU Exporter (ghidra-ml-gpu-exporter)...${NC}"
GPU_CAPS=$(docker exec $GPU_EXPORTER bash -c "grep CapEff /proc/self/status | awk '{print \$2}'" 2>/dev/null || echo "N/A")
if echo "$GPU_CAPS" | grep -q "0000003fffffffff\|00000000a80425fb"; then
    test_result "GPU Exporter over-privileged" "FAIL" "CAP_SYS_ADMIN detected (CRITICAL RISK)"
else
    test_result "GPU Exporter capabilities" "PASS" "Minimal capabilities"
fi

# Test 3: GPU Device Isolation
echo -e "\n${BLUE}[Test 3] GPU Device Isolation${NC}"
echo "───────────────────────────────────────"

# Test 3.1: Check accessible NVIDIA devices
NVIDIA_DEVS=$(docker exec $CONTAINER_NAME ls /dev/nvidia* 2>/dev/null | wc -l)
if [ "$NVIDIA_DEVS" -gt 0 ] && [ "$NVIDIA_DEVS" -lt 10 ]; then
    test_result "GPU device access" "PASS" "Only NVIDIA GPU devices accessible ($NVIDIA_DEVS devices)"
else
    test_result "GPU device access" "WARN" "Unexpected device count: $NVIDIA_DEVS"
fi

# Test 3.2: No NVMe/storage device access
if docker exec $CONTAINER_NAME bash -c "ls /dev/nvme* /dev/sd* /dev/vd*" 2>&1 | grep -q "No such file"; then
    test_result "Storage device isolation" "PASS" "No host storage devices accessible"
else
    test_result "Storage device isolation" "FAIL" "Can access host storage devices"
fi

# Test 3.3: GPU memory access validation
if docker exec $CONTAINER_NAME python3 -c "import torch; assert torch.cuda.is_available()" 2>&1 | grep -q ""; then
    test_result "GPU functional access" "PASS" "PyTorch can access GPU"
else
    test_result "GPU functional access" "FAIL" "PyTorch cannot access GPU"
fi

# Test 4: Network Namespace Isolation
echo -e "\n${BLUE}[Test 4] Network Namespace Isolation${NC}"
echo "───────────────────────────────────────"

# Test 4.1: Check network interfaces
NET_IFACES=$(docker exec $CONTAINER_NAME ip addr show | grep -c "^[0-9]")
if [ "$NET_IFACES" -le 2 ]; then
    test_result "Network interface isolation" "PASS" "Only container interfaces present ($NET_IFACES)"
else
    test_result "Network interface isolation" "WARN" "Multiple interfaces: $NET_IFACES"
fi

# Test 4.2: Host network unreachability
if docker exec $CONTAINER_NAME bash -c "timeout 2 ping -c 1 172.17.0.1" 2>&1 | grep -q "Network is unreachable\|timed out\|Destination Host Unreachable"; then
    test_result "Host network isolation" "PASS" "Cannot reach host network"
else
    test_result "Host network isolation" "WARN" "May have host network access"
fi

# Test 5: Volume Security
echo -e "\n${BLUE}[Test 5] Read-Only Volume Enforcement${NC}"
echo "───────────────────────────────────────"

# Test 5.1: /models read-only
if docker exec $CONTAINER_NAME bash -c "touch /models/test_file" 2>&1 | grep -q "Read-only file system"; then
    test_result "/models read-only enforcement" "PASS" "Cannot write to /models"
else
    test_result "/models read-only enforcement" "FAIL" "Can write to /models"
fi

# Test 5.2: /app read-only
if docker exec $CONTAINER_NAME bash -c "echo 'malicious' > /app/test.py" 2>&1 | grep -q "Read-only file system\|Permission denied"; then
    test_result "/app read-only enforcement" "PASS" "Cannot write to /app"
else
    test_result "/app read-only enforcement" "FAIL" "Can write to /app"
fi

# Test 5.3: /tmp writable (required for PyTorch)
if docker exec $CONTAINER_NAME bash -c "touch /tmp/test_write && rm /tmp/test_write"; then
    test_result "/tmp writable (required)" "PASS" "PyTorch can write compilation cache"
else
    test_result "/tmp writable (required)" "FAIL" "Cannot write to /tmp (PyTorch will fail)"
fi

# Test 6: User Namespace & Process Isolation
echo -e "\n${BLUE}[Test 6] User Namespace & Process Isolation${NC}"
echo "───────────────────────────────────────"

# Test 6.1: Non-root execution
CONTAINER_UID=$(docker exec $CONTAINER_NAME id -u)
if [ "$CONTAINER_UID" != "0" ]; then
    test_result "Non-root execution" "PASS" "Running as UID $CONTAINER_UID"
else
    test_result "Non-root execution" "FAIL" "Running as root (UID 0)"
fi

# Test 6.2: No-new-privileges enforcement
if docker inspect $CONTAINER_NAME | grep -q '"NoNewPrivileges": true'; then
    test_result "no-new-privileges flag" "PASS" "Privilege escalation prevented"
else
    test_result "no-new-privileges flag" "FAIL" "no-new-privileges not set"
fi

# Test 6.3: PID namespace isolation
PID1=$(docker exec $CONTAINER_NAME bash -c "ps aux | grep -c '^'")
if [ "$PID1" -lt 20 ]; then
    test_result "PID namespace isolation" "PASS" "Isolated PID namespace ($PID1 processes)"
else
    test_result "PID namespace isolation" "WARN" "Many processes visible: $PID1"
fi

# Test 7: Docker Socket Exposure (cAdvisor)
echo -e "\n${BLUE}[Test 7] Docker Socket Exposure Risk${NC}"
echo "───────────────────────────────────────"

# Test 7.1: Check if Docker socket is mounted
if docker exec $CADVISOR ls /var/run/docker.sock 2>&1 | grep -q "docker.sock"; then
    test_result "Docker socket exposure" "WARN" "cAdvisor has Docker socket access (MEDIUM RISK)"
else
    test_result "Docker socket exposure" "PASS" "No Docker socket mounted"
fi

# Test 7.2: Check if Docker socket is read-only
if docker inspect $CADVISOR | grep -q '"Source": "/var/run/docker.sock".*"RW": false'; then
    test_result "Docker socket read-only" "PASS" "Docker socket is read-only"
else
    test_result "Docker socket read-only" "WARN" "Docker socket may be writable"
fi

# Test 8: Resource Limits
echo -e "\n${BLUE}[Test 8] Resource Limit Enforcement${NC}"
echo "───────────────────────────────────────"

# Test 8.1: Memory limit
MEM_LIMIT=$(docker inspect $CONTAINER_NAME | grep '"Memory"' | head -1 | grep -o '[0-9]*')
if [ "$MEM_LIMIT" -gt 0 ] && [ "$MEM_LIMIT" -le 6442450944 ]; then
    test_result "Memory limit enforced" "PASS" "Limit: $(($MEM_LIMIT / 1024 / 1024 / 1024))GB"
else
    test_result "Memory limit enforced" "WARN" "Memory limit: $MEM_LIMIT bytes"
fi

# Test 8.2: CPU limit
CPU_LIMIT=$(docker inspect $CONTAINER_NAME | grep '"NanoCpus"' | grep -o '[0-9]*')
if [ "$CPU_LIMIT" -gt 0 ] && [ "$CPU_LIMIT" -le 4000000000 ]; then
    test_result "CPU limit enforced" "PASS" "Limit: $(($CPU_LIMIT / 1000000000)) cores"
else
    test_result "CPU limit enforced" "WARN" "CPU limit: $CPU_LIMIT nanocpus"
fi

# Final Summary
echo -e "\n╔══════════════════════════════════════════════════════════════════╗"
echo -e "║                   VALIDATION SUMMARY                             ║"
echo -e "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}✅ PASSED:${NC} $PASS_COUNT tests"
echo -e "${YELLOW}⚠️  WARNINGS:${NC} $WARN_COUNT tests"
echo -e "${RED}❌ FAILED:${NC} $FAIL_COUNT tests"
echo ""

# Security Score Calculation
TOTAL_TESTS=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
SECURITY_SCORE=$(( (PASS_COUNT * 100) / TOTAL_TESTS ))

echo -e "Security Score: ${SECURITY_SCORE}%"
echo ""

# Critical Issues
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}CRITICAL ISSUES DETECTED:${NC}"
    echo "  • $FAIL_COUNT security tests failed"
    echo "  • Review WIZ_ZERODAY_CLOUD_2025_DEFENSE_STRATEGY.md for remediation"
    echo ""
fi

# High-Risk Warnings
if grep -q "CAP_SYS_ADMIN" <<< "$(docker exec $GPU_EXPORTER bash -c 'capsh --print 2>/dev/null')"; then
    echo -e "${RED}🚨 CRITICAL:${NC} GPU Exporter has CAP_SYS_ADMIN capability"
    echo "   This is a HIGH-RISK container escape vector!"
    echo "   Remediate immediately before competition submission."
    echo ""
fi

# Competition Readiness Assessment
echo "═══════════════════════════════════════════════════════════════════"
echo "Wiz ZeroDay.Cloud 2025 - Competition Readiness"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

if [ "$SECURITY_SCORE" -ge 90 ] && [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✅ READY FOR DEFENSIVE SUBMISSION${NC}"
    echo "   • Security score above 90%"
    echo "   • No critical failures"
    echo "   • Defense-in-depth validated"
elif [ "$SECURITY_SCORE" -ge 75 ]; then
    echo -e "${YELLOW}⚠️  PARTIALLY READY${NC}"
    echo "   • Address warnings before submission"
    echo "   • Review attack surface analysis"
    echo "   • Consider additional hardening"
else
    echo -e "${RED}❌ NOT READY${NC}"
    echo "   • Critical security gaps identified"
    echo "   • Remediate failures immediately"
    echo "   • Re-run validation after fixes"
fi

echo ""
echo "Next Steps:"
echo "1. Review full analysis: development/WIZ_ZERODAY_CLOUD_2025_DEFENSE_STRATEGY.md"
echo "2. Address critical issues (CAP_SYS_ADMIN on GPU exporter)"
echo "3. Implement recommended hardening (AppArmor, seccomp)"
echo "4. Contact: zerodaycloud@wiz.io for submission guidance"
echo ""
echo "═══════════════════════════════════════════════════════════════════"

# Exit with appropriate code
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
elif [ "$WARN_COUNT" -gt 0 ]; then
    exit 2
else
    exit 0
fi
