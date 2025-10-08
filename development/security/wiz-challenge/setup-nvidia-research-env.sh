#!/bin/bash
# NVIDIA Container Toolkit Security Research Environment Setup
# For Wiz Zero Day Cloud 2025 Competition
# Created: October 6, 2025

set -e  # Exit on error

echo "================================================"
echo "NVIDIA Container Toolkit Security Research Lab"
echo "Environment Setup Script"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create research directory structure
echo -e "${YELLOW}[1/10] Creating research directory structure...${NC}"
mkdir -p ~/nvidia-toolkit-research/{baseline,screenshots,detection,hardening,findings}
cd ~/nvidia-toolkit-research

# Update system
echo -e "${YELLOW}[2/10] Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# Install prerequisites
echo -e "${YELLOW}[3/10] Installing build tools and prerequisites...${NC}"
sudo apt install -y \
    build-essential \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common

# Install Docker Engine
echo -e "${YELLOW}[4/10] Installing Docker Engine...${NC}"
if ! command -v docker &> /dev/null; then
    # Remove old versions
    sudo apt remove docker docker-engine docker.io containerd runc 2>/dev/null || true

    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

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
    sudo service docker start

    echo -e "${GREEN}✓ Docker installed successfully${NC}"
else
    echo -e "${GREEN}✓ Docker already installed${NC}"
fi

# Install NVIDIA Container Toolkit
echo -e "${YELLOW}[5/10] Installing NVIDIA Container Toolkit...${NC}"
if ! command -v nvidia-ctk &> /dev/null; then
    # Add NVIDIA repository
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
      sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
      sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

    sudo apt update
    sudo apt install -y nvidia-container-toolkit

    # Configure Docker runtime
    sudo nvidia-ctk runtime configure --runtime=docker
    sudo service docker restart

    echo -e "${GREEN}✓ NVIDIA Container Toolkit installed${NC}"
else
    echo -e "${GREEN}✓ NVIDIA Container Toolkit already installed${NC}"
fi

# Verify installations
echo -e "${YELLOW}[6/10] Verifying installations...${NC}"
echo "Docker version: $(docker --version)"
echo "NVIDIA Container Toolkit version: $(nvidia-ctk --version)"

# Install security monitoring tools
echo -e "${YELLOW}[7/10] Installing security monitoring tools...${NC}"

# Falco
if ! command -v falco &> /dev/null; then
    curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo apt-key add -
    echo "deb https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
    sudo apt update
    sudo apt install -y falco
    echo -e "${GREEN}✓ Falco installed${NC}"
else
    echo -e "${GREEN}✓ Falco already installed${NC}"
fi

# Additional security tools
sudo apt install -y \
    auditd \
    audispd-plugins \
    apparmor \
    apparmor-utils \
    strace \
    ltrace \
    tcpdump

# Install Trivy for container scanning
if ! command -v trivy &> /dev/null; then
    wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.deb
    sudo dpkg -i trivy_0.48.0_Linux-64bit.deb
    rm trivy_0.48.0_Linux-64bit.deb
    echo -e "${GREEN}✓ Trivy installed${NC}"
else
    echo -e "${GREEN}✓ Trivy already installed${NC}"
fi

# Install Docker Bench Security
echo -e "${YELLOW}[8/10] Installing Docker Bench Security...${NC}"
if [ ! -d ~/docker-bench-security ]; then
    cd ~
    git clone https://github.com/docker/docker-bench-security.git
    echo -e "${GREEN}✓ Docker Bench Security cloned${NC}"
else
    echo -e "${GREEN}✓ Docker Bench Security already exists${NC}"
fi

cd ~/nvidia-toolkit-research

# Capture baseline configuration
echo -e "${YELLOW}[9/10] Capturing baseline configuration...${NC}"
echo "System Information:" > baseline/system-info.txt
uname -a >> baseline/system-info.txt
echo "" >> baseline/system-info.txt
echo "Docker Information:" >> baseline/system-info.txt
docker info >> baseline/system-info.txt 2>&1 || echo "Docker not accessible (may need to re-login for group permissions)" >> baseline/system-info.txt
echo "" >> baseline/system-info.txt
echo "NVIDIA Container Toolkit Version:" >> baseline/system-info.txt
nvidia-ctk --version >> baseline/system-info.txt 2>&1

# Copy configuration files
sudo cp /etc/docker/daemon.json baseline/ 2>/dev/null || echo "{}" > baseline/daemon.json
sudo cp /etc/nvidia-container-runtime/config.toml baseline/ 2>/dev/null || echo "Config not found" > baseline/config.toml

# Test GPU accessibility (will work after relogin)
echo -e "${YELLOW}[10/10] Testing GPU container (may require re-login)...${NC}"
docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi > baseline/gpu-test.txt 2>&1 || \
    echo "GPU test failed - you may need to re-login for docker group permissions" > baseline/gpu-test.txt

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Environment Setup Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Research directory: ~/nvidia-toolkit-research"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC} You may need to log out and back in for docker group permissions to take effect."
echo "After re-logging, run: docker run --rm --runtime=nvidia --gpus all nvidia/cuda:12.2.0-base-ubuntu22.04 nvidia-smi"
echo ""
echo "Next steps:"
echo "1. Deploy Falco detection rules"
echo "2. Run Docker Bench Security audit"
echo "3. Begin vulnerability analysis"
echo ""
echo "Documentation: ~/nvidia-toolkit-research/baseline/"
