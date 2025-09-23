#!/usr/bin/env python3
"""
STOOPIDPC Optimized Configuration
Designed for resource-constrained hardware
"""

import os
import psutil
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class HardwareProfile:
    total_memory_gb: float
    available_memory_gb: float
    cpu_cores: int
    profile_name: str
    recommended_config: Dict


class STOOPIDPCOptimizer:
    """Automatically optimize Kubernetes configuration for available hardware"""

    def __init__(self):
        self.hardware = self.detect_hardware()
        self.profile = self.determine_profile()

    def detect_hardware(self) -> Dict:
        """Detect current system hardware"""
        try:
            # Get system info
            memory = psutil.virtual_memory()
            cpu_count = psutil.cpu_count(logical=False) or 1
            cpu_count_logical = psutil.cpu_count(logical=True) or 2

            hardware = {
                "total_memory_gb": memory.total / (1024**3),
                "available_memory_gb": memory.available / (1024**3),
                "used_memory_gb": memory.used / (1024**3),
                "memory_percent": memory.percent,
                "cpu_cores_physical": cpu_count,
                "cpu_cores_logical": cpu_count_logical,
                "cpu_usage_percent": psutil.cpu_percent(interval=1)
            }

            return hardware
        except:
            # Fallback if psutil isn't available
            return {
                "total_memory_gb": 4.0,
                "available_memory_gb": 2.0,
                "used_memory_gb": 2.0,
                "memory_percent": 50.0,
                "cpu_cores_physical": 2,
                "cpu_cores_logical": 4,
                "cpu_usage_percent": 50.0
            }

    def determine_profile(self) -> HardwareProfile:
        """Determine optimal configuration based on hardware"""

        total_ram = self.hardware["total_memory_gb"]
        available_ram = self.hardware["available_memory_gb"]
        cpu_cores = self.hardware["cpu_cores_physical"]

        # Ultra Low Spec (< 2GB RAM)
        if total_ram < 2:
            return HardwareProfile(
                total_memory_gb=total_ram,
                available_memory_gb=available_ram,
                cpu_cores=cpu_cores,
                profile_name="ULTRA_LOW_SPEC",
                recommended_config={
                    "deployment_mode": "remote_only",
                    "local_kubernetes": False,
                    "agent_mode": "lightweight",
                    "monitoring_interval": 60,
                    "max_local_pods": 0,
                    "message": "System can only run management agents for remote clusters"
                }
            )

        # Low Spec (2-4GB RAM)
        elif total_ram < 4:
            return HardwareProfile(
                total_memory_gb=total_ram,
                available_memory_gb=available_ram,
                cpu_cores=cpu_cores,
                profile_name="LOW_SPEC",
                recommended_config={
                    "deployment_mode": "minimal_local",
                    "local_kubernetes": "k3s",
                    "agent_mode": "conservative",
                    "monitoring_interval": 30,
                    "max_local_pods": 1,
                    "pod_cpu_limit": "500m",
                    "pod_memory_limit": "512Mi",
                    "message": "Can run K3s with 1 minimal pod for testing"
                }
            )

        # Medium Spec (4-8GB RAM)
        elif total_ram < 8:
            return HardwareProfile(
                total_memory_gb=total_ram,
                available_memory_gb=available_ram,
                cpu_cores=cpu_cores,
                profile_name="MEDIUM_SPEC",
                recommended_config={
                    "deployment_mode": "development",
                    "local_kubernetes": "minikube",
                    "agent_mode": "balanced",
                    "monitoring_interval": 20,
                    "max_local_pods": 2,
                    "pod_cpu_limit": "1",
                    "pod_memory_limit": "1Gi",
                    "message": "Good for development with 1-2 pods"
                }
            )

        # Good Spec (8-16GB RAM)
        elif total_ram < 16:
            return HardwareProfile(
                total_memory_gb=total_ram,
                available_memory_gb=available_ram,
                cpu_cores=cpu_cores,
                profile_name="GOOD_SPEC",
                recommended_config={
                    "deployment_mode": "staging",
                    "local_kubernetes": "docker-desktop",
                    "agent_mode": "standard",
                    "monitoring_interval": 15,
                    "max_local_pods": 3,
                    "pod_cpu_limit": "2",
                    "pod_memory_limit": "2Gi",
                    "message": "Can simulate small production environment"
                }
            )

        # High Spec (16GB+ RAM)
        else:
            max_pods = min(5, int(total_ram / 4))  # ~4GB per pod
            return HardwareProfile(
                total_memory_gb=total_ram,
                available_memory_gb=available_ram,
                cpu_cores=cpu_cores,
                profile_name="HIGH_SPEC",
                recommended_config={
                    "deployment_mode": "production_sim",
                    "local_kubernetes": "docker-desktop",
                    "agent_mode": "full",
                    "monitoring_interval": 10,
                    "max_local_pods": max_pods,
                    "pod_cpu_limit": "4",
                    "pod_memory_limit": "4Gi",
                    "message": f"Can run {max_pods} pods locally for production simulation"
                }
            )

    def generate_deployment_config(self) -> str:
        """Generate optimized deployment configuration"""

        config = self.profile.recommended_config

        if not config.get("local_kubernetes"):
            return self.generate_remote_config()

        return f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catalytic-api-stoopidpc
  namespace: catalytic-lattice
spec:
  replicas: {config.get('max_local_pods', 1)}
  selector:
    matchLabels:
      app: catalytic-api
  template:
    metadata:
      labels:
        app: catalytic-api
        environment: stoopidpc
    spec:
      containers:
      - name: api
        image: catalytic/api:lightweight
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: "{config.get('pod_cpu_limit', '500m')}"
            memory: "{config.get('pod_memory_limit', '512Mi')}"
          requests:
            cpu: "250m"
            memory: "256Mi"
        env:
        - name: NODE_ENV
          value: development
        - name: LOW_RESOURCE_MODE
          value: "true"
        - name: MAX_CONNECTIONS
          value: "50"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: catalytic-api-service
  namespace: catalytic-lattice
spec:
  selector:
    app: catalytic-api
  ports:
  - port: 8080
    targetPort: 8080
  type: NodePort  # Use NodePort for local access
"""

    def generate_remote_config(self) -> str:
        """Generate configuration for remote cluster management"""
        return """
# STOOPIDPC Remote Management Configuration
# ==========================================
# Your system is optimized for managing remote Kubernetes clusters
# rather than running local workloads.

# Install these tools:
# 1. Python 3.8+ (for agents)
# 2. kubectl (for cluster management)
# 3. Cloud CLI (gcloud/aws/az)

# Run agents in lightweight mode:
python deployment/deploy-agent.py --remote --lightweight
python monitoring/health-monitor-agent.py --remote --low-resource
python scaling/auto-scaling-agent.py --remote --conservative

# Connect to remote clusters:
# GKE: gcloud container clusters get-credentials [cluster-name]
# EKS: aws eks update-kubeconfig --name [cluster-name]
# AKS: az aks get-credentials --name [cluster-name] --resource-group [rg]
"""

    def generate_optimization_script(self) -> str:
        """Generate system optimization script"""

        if os.name == 'nt':  # Windows
            return f"""@echo off
REM STOOPIDPC Optimization Script for Windows
REM =========================================

echo Optimizing system for Kubernetes agents...

REM Stop unnecessary services to free memory
echo Stopping unnecessary services...
net stop "Windows Search" /y 2>nul
net stop "Print Spooler" /y 2>nul
net stop "Windows Update" /y 2>nul

REM Set process priority
echo Setting high priority for Python...
wmic process where name="python.exe" CALL setpriority "high priority"

REM Configure Docker Desktop (if installed)
if exist "%PROGRAMFILES%\\Docker\\Docker\\Docker Desktop.exe" (
    echo Configuring Docker Desktop for low resources...
    REM Limit Docker resources
    echo {{
    echo   "memoryMiB": {int(self.hardware['total_memory_gb'] * 512)},
    echo   "cpus": {max(1, self.hardware['cpu_cores_physical'] - 1)},
    echo   "diskSizeMiB": 20480
    echo }} > "%APPDATA%\\Docker\\settings.json"
)

echo.
echo System optimized for profile: {self.profile.profile_name}
echo RAM: {self.hardware['total_memory_gb']:.1f}GB
echo CPU Cores: {self.hardware['cpu_cores_physical']}
echo Recommended: {self.profile.recommended_config.get('message', 'Check configuration')}
echo.
pause
"""
        else:  # Linux/Mac
            return f"""#!/bin/bash
# STOOPIDPC Optimization Script for Linux/Mac
# ===========================================

echo "Optimizing system for Kubernetes agents..."

# Free up memory
echo "Clearing caches..."
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches

# Optimize swappiness for low memory systems
if [ {self.hardware['total_memory_gb']} -lt 8 ]; then
    echo "Setting swappiness for low memory..."
    sudo sysctl vm.swappiness=10
fi

# Configure Docker resource limits
if command -v docker &> /dev/null; then
    echo "Configuring Docker for low resources..."
    cat > ~/.docker/daemon.json <<EOF
{{
  "default-ulimits": {{
    "memlock": {{
      "Name": "memlock",
      "Hard": -1,
      "Soft": -1
    }}
  }},
  "max-concurrent-downloads": 2,
  "max-concurrent-uploads": 2,
  "memory": {int(self.hardware['total_memory_gb'] * 0.5)}g,
  "memory-swap": {int(self.hardware['total_memory_gb'])}g,
  "cpus": "{max(1, self.hardware['cpu_cores_physical'] - 1)}"
}}
EOF
    sudo systemctl restart docker
fi

echo ""
echo "System optimized for profile: {self.profile.profile_name}"
echo "RAM: {self.hardware['total_memory_gb']:.1f}GB"
echo "CPU Cores: {self.hardware['cpu_cores_physical']}"
echo "Recommended: {self.profile.recommended_config.get('message', 'Check configuration')}"
"""

    def print_report(self):
        """Print hardware analysis report"""
        print("\n" + "=" * 60)
        print("  STOOPIDPC HARDWARE ANALYSIS")
        print("=" * 60)

        print(f"\n[System Specifications]")
        print(f"  Total RAM: {self.hardware['total_memory_gb']:.1f} GB")
        print(f"  Available RAM: {self.hardware['available_memory_gb']:.1f} GB")
        print(f"  CPU Cores: {self.hardware['cpu_cores_physical']} physical, {self.hardware['cpu_cores_logical']} logical")
        print(f"  Current CPU Usage: {self.hardware['cpu_usage_percent']:.1f}%")
        print(f"  Current Memory Usage: {self.hardware['memory_percent']:.1f}%")

        print(f"\n[Profile Detection]")
        print(f"  Profile: {self.profile.profile_name}")
        print(f"  Mode: {self.profile.recommended_config['deployment_mode']}")

        print(f"\n[Recommendations]")
        config = self.profile.recommended_config
        print(f"  {config['message']}")

        if config.get('local_kubernetes'):
            print(f"\n  Local Kubernetes: {config['local_kubernetes']}")
            print(f"  Max Local Pods: {config.get('max_local_pods', 0)}")
            print(f"  Pod CPU Limit: {config.get('pod_cpu_limit', 'N/A')}")
            print(f"  Pod Memory Limit: {config.get('pod_memory_limit', 'N/A')}")
        else:
            print(f"\n  Local Kubernetes: Not recommended")
            print(f"  Use Mode: Remote cluster management only")

        print(f"\n[Optimization Commands]")

        if self.profile.profile_name in ["ULTRA_LOW_SPEC", "LOW_SPEC"]:
            print("  # Use K3s for minimal footprint")
            print("  curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE='644' sh -")
            print("  # Or manage remote clusters only")
            print("  kubectl config use-context [remote-cluster]")
        elif self.profile.profile_name == "MEDIUM_SPEC":
            print("  # Use Minikube with limited resources")
            print(f"  minikube start --memory={int(self.hardware['total_memory_gb'] * 512)} --cpus={max(1, self.hardware['cpu_cores_physical']-1)}")
        else:
            print("  # Use Docker Desktop Kubernetes")
            print("  # Enable in Docker Desktop settings")

        print("\n" + "=" * 60)


def main():
    """Run STOOPIDPC hardware analysis and optimization"""

    print("\nInitializing STOOPIDPC Optimizer...")
    optimizer = STOOPIDPCOptimizer()

    # Print analysis report
    optimizer.print_report()

    # Generate configurations
    print("\n[Generating Optimized Configurations]")

    # Save deployment config
    deployment_yaml = optimizer.generate_deployment_config()
    config_file = "stoopidpc-deployment.yaml"
    with open(config_file, "w") as f:
        f.write(deployment_yaml)
    print(f"  Created: {config_file}")

    # Save optimization script
    script_ext = ".bat" if os.name == 'nt' else ".sh"
    script_file = f"optimize-stoopidpc{script_ext}"
    optimization_script = optimizer.generate_optimization_script()
    with open(script_file, "w") as f:
        f.write(optimization_script)
    print(f"  Created: {script_file}")

    # Provide quick start commands
    print("\n[Quick Start Commands]")
    config = optimizer.profile.recommended_config

    if config.get('max_local_pods', 0) > 0:
        print(f"\n  1. Apply optimized deployment:")
        print(f"     kubectl apply -f {config_file}")

        print(f"\n  2. Run agents with resource limits:")
        print(f"     python deployment/deploy-agent.py --max-pods {config['max_local_pods']}")
        print(f"     python monitoring/health-monitor-agent.py --interval {config['monitoring_interval']}")
        print(f"     python scaling/auto-scaling-agent.py --mode {config['agent_mode']}")
    else:
        print(f"\n  Your system is best suited for remote cluster management.")
        print(f"  1. Install kubectl and cloud CLI tools")
        print(f"  2. Configure remote cluster access")
        print(f"  3. Run agents in lightweight mode")

    print("\n[Summary]")
    print(f"  [YES] STOOPIDPC CAN run this program!")
    print(f"  Profile: {optimizer.profile.profile_name}")
    print(f"  Best Use: {config['deployment_mode'].replace('_', ' ').title()}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()