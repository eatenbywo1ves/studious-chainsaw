#!/usr/bin/env python3
"""
STOOPIDPC Capability Verification
Confirms the system can run the Catalytic Lattice K8s workload
"""

import psutil
import platform
import sys

def format_bytes(bytes_value):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f}{unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f}PB"

def check_capability():
    """Check if STOOPIDPC can run the workload"""

    print("\n" + "=" * 60)
    print("  STOOPIDPC CAPABILITY VERIFICATION")
    print("=" * 60)

    # System info
    print("\n[SYSTEM INFORMATION]")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  Architecture: {platform.machine()}")
    print(f"  Processor: {platform.processor()}")
    print(f"  Python: {sys.version.split()[0]}")

    # Memory check
    memory = psutil.virtual_memory()
    print("\n[MEMORY ANALYSIS]")
    print(f"  Total RAM: {format_bytes(memory.total)}")
    print(f"  Available: {format_bytes(memory.available)}")
    print(f"  Used: {format_bytes(memory.used)} ({memory.percent:.1f}%)")

    # CPU check
    print("\n[CPU ANALYSIS]")
    print(f"  Physical Cores: {psutil.cpu_count(logical=False)}")
    print(f"  Logical Cores: {psutil.cpu_count(logical=True)}")
    print(f"  Current Usage: {psutil.cpu_percent(interval=1):.1f}%")

    # Disk check
    disk = psutil.disk_usage('/')
    print("\n[DISK ANALYSIS]")
    print(f"  Total Space: {format_bytes(disk.total)}")
    print(f"  Free Space: {format_bytes(disk.free)}")
    print(f"  Used: {format_bytes(disk.used)} ({disk.percent:.1f}%)")

    # Capability assessment
    print("\n[CAPABILITY ASSESSMENT]")
    print("-" * 40)

    total_ram_gb = memory.total / (1024**3)
    cpu_cores = psutil.cpu_count(logical=False) or 1

    capabilities = []

    # Check for different scenarios
    if total_ram_gb >= 64 and cpu_cores >= 6:
        capabilities.append(("[EXCELLENT]", "Full production simulation (5-10 pods)"))
        capabilities.append(("[YES]", "Local Kubernetes cluster"))
        capabilities.append(("[YES]", "All agents with full monitoring"))
        capabilities.append(("[YES]", "Auto-scaling with 20 replicas max"))
        verdict = "PRODUCTION READY"

    elif total_ram_gb >= 32 and cpu_cores >= 4:
        capabilities.append(("[GOOD]", "Production simulation (3-5 pods)"))
        capabilities.append(("[YES]", "Docker Desktop Kubernetes"))
        capabilities.append(("[YES]", "All agents running"))
        capabilities.append(("[YES]", "Auto-scaling with 10 replicas max"))
        verdict = "FULLY CAPABLE"

    elif total_ram_gb >= 16:
        capabilities.append(("[OK]", "Development environment (2-3 pods)"))
        capabilities.append(("[YES]", "Minikube or K3s"))
        capabilities.append(("[YES]", "Agents with conservative settings"))
        capabilities.append(("[LIMITED]", "Auto-scaling with 5 replicas max"))
        verdict = "DEVELOPMENT READY"

    elif total_ram_gb >= 8:
        capabilities.append(("[LIMITED]", "Testing only (1-2 pods)"))
        capabilities.append(("[YES]", "K3s lightweight"))
        capabilities.append(("[YES]", "Agents in lightweight mode"))
        capabilities.append(("[NO]", "Limited auto-scaling"))
        verdict = "TESTING CAPABLE"

    elif total_ram_gb >= 4:
        capabilities.append(("[MINIMAL]", "Single pod testing"))
        capabilities.append(("[MAYBE]", "K3s with minimal config"))
        capabilities.append(("[YES]", "Remote cluster management"))
        capabilities.append(("[NO]", "Local auto-scaling not recommended"))
        verdict = "REMOTE MANAGEMENT"

    else:
        capabilities.append(("[NO]", "Local Kubernetes"))
        capabilities.append(("[NO]", "Local pods"))
        capabilities.append(("[YES]", "Remote cluster management only"))
        capabilities.append(("[YES]", "Agents for remote clusters"))
        verdict = "REMOTE ONLY"

    for status, capability in capabilities:
        print(f"  {status} {capability}")

    # Final verdict
    print("\n[FINAL VERDICT]")
    print("=" * 40)
    print(f"  STOOPIDPC Status: {verdict}")
    print(f"  RAM Score: {min(100, int(total_ram_gb / 64 * 100))}/100")
    print(f"  CPU Score: {min(100, int(cpu_cores / 8 * 100))}/100")

    if total_ram_gb >= 4:
        print(f"\n  [RESULT] YES, STOOPIDPC CAN RUN THIS PROGRAM!")

        if total_ram_gb >= 64:
            print(f"  [NOTE] Exceptional hardware detected!")
            print(f"         Can handle full production workload locally")
        elif total_ram_gb >= 16:
            print(f"  [NOTE] Good hardware for development/staging")
        else:
            print(f"  [NOTE] Suitable for testing and remote management")
    else:
        print(f"\n  [RESULT] LIMITED - Remote management only")
        print(f"  [NOTE] Upgrade RAM to 8GB+ for local Kubernetes")

    # Recommendations
    print("\n[RECOMMENDED COMMANDS]")
    if total_ram_gb >= 16:
        print("  # Full deployment with monitoring")
        print("  python orchestrator.py")
        print("  # Or run individually:")
        print("  python deployment/deploy-agent.py local")
        print("  python monitoring/health-monitor-agent.py")
        print("  python scaling/auto-scaling-agent.py")
    elif total_ram_gb >= 8:
        print("  # Lightweight deployment")
        print("  python deployment/deploy-agent.py local --lightweight")
        print("  python monitoring/health-monitor-agent.py --interval 60")
    else:
        print("  # Remote cluster management")
        print("  kubectl config use-context [remote-cluster]")
        print("  python deployment/deploy-agent.py gke")
        print("  python monitoring/health-monitor-agent.py --remote")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    check_capability()