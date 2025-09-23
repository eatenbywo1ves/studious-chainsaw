#!/usr/bin/env python3
"""
Demo script to showcase agent capabilities without actual Kubernetes cluster
"""

import random
import time
from datetime import datetime

def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def demo_deployment_agent():
    """Demonstrate deployment agent capabilities"""
    print_header("DEPLOYMENT AGENT DEMO")

    print("\nSimulating deployment to Kubernetes cluster...")
    print("-" * 40)

    # Simulate prerequisite checks
    print("\n[Phase 1] Prerequisites Check:")
    prerequisites = [
        ("Docker", True, "v20.10.17"),
        ("kubectl", True, "v1.25.0"),
        ("Cluster Access", True, "docker-desktop")
    ]

    for tool, status, version in prerequisites:
        status_str = "[OK]" if status else "[FAIL]"
        print(f"  {status_str} {tool}: {version}")

    # Simulate deployment steps
    print("\n[Phase 2] Deployment Process:")
    steps = [
        "Creating namespace 'catalytic-lattice'",
        "Applying deployment manifest",
        "Creating service 'catalytic-api-service'",
        "Configuring horizontal pod autoscaler",
        "Setting up ingress rules"
    ]

    for i, step in enumerate(steps, 1):
        print(f"  [{i}/5] {step}...", end="")
        time.sleep(0.5)
        print(" [OK]")

    print("\n[Phase 3] Verification:")
    print(f"  Deployment: catalytic-api")
    print(f"  Replicas: 3/3 ready")
    print(f"  Service: LoadBalancer (Pending)")
    print(f"  Endpoint: http://localhost:8080")

    print("\n[SUCCESS] Deployment completed successfully!")

def demo_health_monitor():
    """Demonstrate health monitoring capabilities"""
    print_header("HEALTH MONITOR AGENT DEMO")

    print("\nGenerating Health Report...")
    print("-" * 40)

    # Simulate health metrics
    cpu_usage = random.uniform(45, 75)
    memory_usage = random.uniform(50, 70)
    response_time = random.uniform(100, 500)
    error_rate = random.uniform(0, 2)

    # Determine overall health
    if cpu_usage > 80 or error_rate > 5:
        overall_status = "[CRITICAL]"
    elif cpu_usage > 70 or error_rate > 2:
        overall_status = "[WARNING]"
    else:
        overall_status = "[OK]"

    print(f"\nOverall Status: {overall_status}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Namespace: catalytic-lattice")

    print("\nHealth Checks:")
    health_checks = [
        ("deployment_status", "[OK]", "All 3 replicas are ready"),
        ("pod_catalytic-api-xyz", "[OK]", "Pod is healthy"),
        ("pod_catalytic-api-abc", "[OK]", "Pod is healthy"),
        ("pod_catalytic-api-def", "[WARNING]", "High memory usage (1 restart)"),
        ("cpu_usage", "[OK]" if cpu_usage < 70 else "[WARNING]", f"CPU usage: {cpu_usage:.1f}%"),
        ("memory_usage", "[OK]", f"Memory usage: {memory_usage:.1f}%"),
        ("error_rate", "[OK]" if error_rate < 2 else "[WARNING]", f"Error rate: {error_rate:.1f}%"),
        ("latency_p95", "[OK]", f"Latency: {response_time:.0f}ms")
    ]

    for name, status, message in health_checks:
        print(f"  {status} {name}: {message}")

    print("\nResource Metrics (Average):")
    print(f"  CPU Usage: {cpu_usage:.1f}%")
    print(f"  Memory Usage: {memory_usage:.1f}%")
    print(f"  Request Rate: {random.uniform(200, 800):.0f} req/s")
    print(f"  Response Time: {response_time:.0f}ms")

    print("\nRecommendations:")
    if cpu_usage > 70:
        print("  1. CPU usage trending high. Consider implementing predictive autoscaling.")
    if memory_usage > 65:
        print("  2. Monitor memory patterns for potential optimization opportunities.")
    if error_rate > 1:
        print("  3. Error rate slightly elevated. Review recent deployments.")
    if cpu_usage < 70 and memory_usage < 65 and error_rate < 1:
        print("  1. System healthy: No immediate actions required.")

def demo_auto_scaling():
    """Demonstrate auto-scaling capabilities"""
    print_header("AUTO-SCALING AGENT DEMO")

    print("\nConfiguration:")
    print("  Namespace: catalytic-lattice")
    print("  Replicas: 3 - 20")
    print("  Target CPU: 70.0%")
    print("  Cooldown: 300s")

    print("\n[WARNING] Running in simulation mode")

    # Simulate multiple scaling cycles
    print("\nRunning scaling analysis...")
    print("-" * 40)

    for cycle in range(3):
        print(f"\n[Cycle {cycle + 1}]")

        # Generate random metrics
        current_replicas = random.randint(3, 8)
        cpu = random.uniform(30, 85)
        memory = random.uniform(40, 75)
        response_time = random.uniform(100, 600)
        request_rate = random.uniform(100, 1000)

        print(f"Current Metrics:")
        print(f"  Replicas: {current_replicas}")
        print(f"  CPU: {cpu:.1f}%")
        print(f"  Memory: {memory:.1f}%")
        print(f"  Response Time: {response_time:.0f}ms")
        print(f"  Request Rate: {request_rate:.0f} req/s")

        # Determine scaling decision
        if cpu > 80 or response_time > 500:
            decision = "SCALE_UP"
            target = min(current_replicas + 2, 20)
            reason = "High CPU usage" if cpu > 80 else "High response time"
        elif cpu < 30 and current_replicas > 3:
            decision = "SCALE_DOWN"
            target = max(current_replicas - 1, 3)
            reason = "Low resource utilization"
        else:
            decision = "NO_ACTION"
            target = current_replicas
            reason = "Metrics within acceptable range"

        print(f"\nScaling Decision: {decision}")
        print(f"  Reason: {reason}")
        if decision != "NO_ACTION":
            print(f"  Target Replicas: {target}")
            print(f"  Action: {'Adding' if target > current_replicas else 'Removing'} "
                  f"{abs(target - current_replicas)} replica(s)")

        # Predictions
        print(f"\nPredictions (10 min):")
        print(f"  Predicted CPU: {cpu + random.uniform(-10, 15):.1f}%")
        print(f"  Predicted Memory: {memory + random.uniform(-5, 10):.1f}%")
        print(f"  Confidence: {random.uniform(70, 95):.0f}%")

        if cycle < 2:
            print("\nWaiting for next cycle...", end="")
            time.sleep(2)
            print(" [OK]")

    print("\n" + "-" * 40)
    print("Scaling Recommendations:")
    print("  1. Business hours detected. Consider scheduled scaling.")
    print("  2. CPU usage pattern stable. Current thresholds optimal.")
    print("  3. No flapping detected in recent scaling history.")

def main():
    """Main demo function"""
    print("\n" + "=" * 60)
    print("  CATALYTIC LATTICE K8S AGENTS - DEMO MODE")
    print("=" * 60)
    print("\nThis demo simulates agent behavior without requiring")
    print("an actual Kubernetes cluster installation.")

    while True:
        print("\n" + "-" * 40)
        print("Select demo to run:")
        print("  1. Deployment Agent")
        print("  2. Health Monitor Agent")
        print("  3. Auto-Scaling Agent")
        print("  4. Run All Demos")
        print("  5. Exit")
        print("-" * 40)

        choice = input("\nEnter choice (1-5): ").strip()

        if choice == "1":
            demo_deployment_agent()
        elif choice == "2":
            demo_health_monitor()
        elif choice == "3":
            demo_auto_scaling()
        elif choice == "4":
            demo_deployment_agent()
            time.sleep(2)
            demo_health_monitor()
            time.sleep(2)
            demo_auto_scaling()
        elif choice == "5":
            print("\nExiting demo. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted. Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")