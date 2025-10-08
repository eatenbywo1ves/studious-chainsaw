#!/bin/bash
# checkpoint-install.sh - Systematic NVIDIA Container Toolkit Installation
# Wiz Zero Day Cloud 2025 Competition
# Created: October 6, 2025

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RESEARCH_DIR="$HOME/nvidia-toolkit-research"
CHECKPOINT_DIR="$RESEARCH_DIR/checkpoints"
LOG_DIR="$RESEARCH_DIR/logs"
BASELINE_DIR="$RESEARCH_DIR/baseline"

# Create directory structure
mkdir -p "$CHECKPOINT_DIR" "$LOG_DIR" "$BASELINE_DIR" \
         "$RESEARCH_DIR"/{screenshots,tests,detection,hardening,findings,metrics}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     NVIDIA Container Toolkit Security Research Lab          ║${NC}"
echo -e "${BLUE}║          Checkpoint-Based Installation System                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Checkpoint function
checkpoint() {
    local name=$1
    local description=$2
    local validation_cmd=$3

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}🔍 CHECKPOINT: $name${NC}"
    echo -e "${YELLOW}   $description${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Check if already completed
    if [ -f "$CHECKPOINT_DIR/$name.done" ]; then
        TIMESTAMP=$(cat "$CHECKPOINT_DIR/$name.done")
        echo -e "${GREEN}✓ ALREADY COMPLETED${NC} (at $TIMESTAMP)"
        echo ""
        return 0
    fi

    # Run validation command
    echo "Running validation: $validation_cmd"
    if eval "$validation_cmd" > "$LOG_DIR/$name.log" 2>&1; then
        echo -e "${GREEN}✓ PASSED: $name${NC}"
        date > "$CHECKPOINT_DIR/$name.done"
        echo ""
        return 0
    else
        echo -e "${RED}✗ FAILED: $name${NC}"
        echo "See log: $LOG_DIR/$name.log"
        echo ""
        return 1
    fi
}

# Checkpoint 1: System verification
checkpoint "01-system-check" \
    "Verify Ubuntu 24.04 LTS" \
    "lsb_release -a | grep -q '24.04'"

# Checkpoint 2: Internet connectivity
checkpoint "02-internet-check" \
    "Verify internet connectivity" \
    "ping -c 1 google.com"

# Checkpoint 3: Sudo access
checkpoint "03-sudo-access" \
    "Verify sudo privileges" \
    "sudo -n true 2>/dev/null || sudo true"

# Checkpoint 4: Docker installation check
echo -e "${BLUE}[Step 1/6] Docker Installation${NC}"
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing..."

    # Remove old versions
    sudo apt remove docker docker-engine docker.io containerd runc 2>/dev/null || true

    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Set up repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Add user to docker group
    sudo usermod -aG docker $USER

    # Start Docker
    sudo service docker start || sudo systemctl start docker

    echo -e "${GREEN}✓ Docker installed${NC}"
else
    echo -e "${GREEN}✓ Docker already installed${NC}"
fi

checkpoint "04-docker-installed" \
    "Verify Docker installation" \
    "docker --version"

# Checkpoint 5: Docker service running
sudo service docker start 2>/dev/null || sudo systemctl start docker 2>/dev/null || true
checkpoint "05-docker-running" \
    "Verify Docker service is running" \
    "docker info"

# Checkpoint 6: NVIDIA Container Toolkit installation
echo ""
echo -e "${BLUE}[Step 2/6] NVIDIA Container Toolkit Installation${NC}"
if ! command -v nvidia-ctk &> /dev/null; then
    echo "NVIDIA Container Toolkit not found. Installing..."

    # Add NVIDIA repository
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
        sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
        sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
        sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

    sudo apt update
    sudo apt install -y nvidia-container-toolkit

    # Configure Docker runtime
    sudo nvidia-ctk runtime configure --runtime=docker
    sudo service docker restart || sudo systemctl restart docker

    echo -e "${GREEN}✓ NVIDIA Container Toolkit installed${NC}"
else
    echo -e "${GREEN}✓ NVIDIA Container Toolkit already installed${NC}"
fi

checkpoint "06-nvidia-toolkit-installed" \
    "Verify NVIDIA Container Toolkit installation" \
    "nvidia-ctk --version"

# Checkpoint 7: NVIDIA Toolkit version check
checkpoint "07-toolkit-version-check" \
    "Verify toolkit version >= 1.17.8 (patched)" \
    "nvidia-ctk --version | grep -qE '1\.17\.[8-9]|1\.1[8-9]\.|1\.[2-9][0-9]\.'"

# Checkpoint 8: GPU container test
echo ""
echo -e "${BLUE}[Step 3/6] GPU Container Functionality Test${NC}"
checkpoint "08-gpu-container-test" \
    "Test GPU container functionality" \
    "timeout 30 docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi"

# Checkpoint 9: Falco installation
echo ""
echo -e "${BLUE}[Step 4/6] Falco Runtime Security Installation${NC}"
if ! command -v falco &> /dev/null; then
    echo "Installing Falco..."

    # Add Falco repository
    curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo apt-key add -
    echo "deb https://download.falco.org/packages/deb stable main" | \
        sudo tee /etc/apt/sources.list.d/falcosecurity.list

    sudo apt update
    sudo apt install -y falco

    echo -e "${GREEN}✓ Falco installed${NC}"
else
    echo -e "${GREEN}✓ Falco already installed${NC}"
fi

checkpoint "09-falco-installed" \
    "Verify Falco installation" \
    "falco --version"

# Checkpoint 10: Falco service running
sudo systemctl enable falco 2>/dev/null || true
sudo systemctl start falco 2>/dev/null || true
checkpoint "10-falco-running" \
    "Verify Falco service is running" \
    "sudo systemctl is-active falco"

# Checkpoint 11: Security tools installation
echo ""
echo -e "${BLUE}[Step 5/6] Additional Security Tools${NC}"
sudo apt install -y auditd apparmor apparmor-utils strace tcpdump git curl wget 2>&1 | \
    tee "$LOG_DIR/security-tools-install.log"

checkpoint "11-security-tools-installed" \
    "Verify security tools installed" \
    "command -v strace && command -v tcpdump"

# Checkpoint 12: Trivy installation
if ! command -v trivy &> /dev/null; then
    echo "Installing Trivy..."
    wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.deb \
        -O /tmp/trivy.deb
    sudo dpkg -i /tmp/trivy.deb
    rm /tmp/trivy.deb
fi

checkpoint "12-trivy-installed" \
    "Verify Trivy container scanner" \
    "trivy --version"

# Checkpoint 13: Docker Bench Security
echo ""
echo -e "${BLUE}[Step 6/6] Docker Bench Security${NC}"
if [ ! -d "$HOME/docker-bench-security" ]; then
    cd ~
    git clone https://github.com/docker/docker-bench-security.git
    cd "$RESEARCH_DIR"
fi

checkpoint "13-docker-bench-available" \
    "Verify Docker Bench Security available" \
    "[ -d $HOME/docker-bench-security ]"

# Baseline configuration capture
echo ""
echo -e "${BLUE}Capturing Baseline Configuration...${NC}"

# System information
uname -a > "$BASELINE_DIR/system-info.txt"
lsb_release -a >> "$BASELINE_DIR/system-info.txt" 2>&1
date >> "$BASELINE_DIR/system-info.txt"

# Docker info
docker info > "$BASELINE_DIR/docker-info.txt" 2>&1

# NVIDIA Toolkit info
nvidia-ctk --version > "$BASELINE_DIR/nvidia-toolkit-version.txt" 2>&1

# NVIDIA Toolkit configuration
sudo cat /etc/nvidia-container-runtime/config.toml > "$BASELINE_DIR/config.toml" 2>/dev/null || \
    echo "Config not found" > "$BASELINE_DIR/config.toml"

# Docker daemon configuration
sudo cat /etc/docker/daemon.json > "$BASELINE_DIR/daemon.json" 2>/dev/null || \
    echo "{}" > "$BASELINE_DIR/daemon.json"

# GPU container test output
docker run --rm --runtime=nvidia --gpus all \
    nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi \
    > "$BASELINE_DIR/gpu-test-output.txt" 2>&1 || \
    echo "GPU test failed" > "$BASELINE_DIR/gpu-test-output.txt"

# Falco version
falco --version > "$BASELINE_DIR/falco-version.txt" 2>&1

checkpoint "14-baseline-captured" \
    "Baseline configuration captured" \
    "[ -f $BASELINE_DIR/system-info.txt ]"

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                Installation Complete!                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Count completed checkpoints
TOTAL=14
COMPLETED=$(ls "$CHECKPOINT_DIR"/*.done 2>/dev/null | wc -l)
PERCENT=$((COMPLETED * 100 / TOTAL))

echo "Completion Status: $COMPLETED/$TOTAL checkpoints ($PERCENT%)"
echo ""

if [ $COMPLETED -eq $TOTAL ]; then
    echo -e "${GREEN}✓ All checkpoints passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Deploy Falco detection rules"
    echo "2. Run Docker Bench Security audit"
    echo "3. Test detection capabilities"
    echo "4. Review baseline configuration"
else
    echo -e "${YELLOW}⚠ Some checkpoints incomplete${NC}"
    echo ""
    echo "Failed checkpoints:"
    for i in $(seq -f "%02g" 1 $TOTAL); do
        if [ ! -f "$CHECKPOINT_DIR/${i}-*.done" ]; then
            ls "$LOG_DIR/${i}-*.log" 2>/dev/null | sed 's/.*\//  - /' || echo "  - Checkpoint $i"
        fi
    done
fi

echo ""
echo "Research directory: $RESEARCH_DIR"
echo "Logs: $LOG_DIR"
echo "Checkpoints: $CHECKPOINT_DIR"
echo "Baseline: $BASELINE_DIR"
echo ""

# Generate progress dashboard
"$RESEARCH_DIR/generate-dashboard.sh" 2>/dev/null || true

echo -e "${BLUE}Installation log saved to: $LOG_DIR/${NC}"
