#!/usr/bin/env python3
"""
Local Deployment Simulator for STOOPIDPC
Simulates full Kubernetes deployment without requiring Docker/K8s installation
"""

import threading
import time
import random
import json
import http.server
import socketserver
from datetime import datetime
from typing import Dict, List
import os
import sys

class Pod:
    """Simulated Kubernetes Pod"""
    def __init__(self, name: str, replica_num: int):
        self.name = name
        self.replica_num = replica_num
        self.status = "Pending"
        self.cpu_usage = 0
        self.memory_usage = 0
        self.requests_handled = 0
        self.errors = 0
        self.start_time = datetime.now()
        self.port = 8080 + replica_num
        self.is_running = False
        self.thread = None

    def start(self):
        """Start the pod"""
        self.status = "Starting"
        time.sleep(random.uniform(1, 3))  # Simulate startup time
        self.status = "Running"
        self.is_running = True

        # Start simulated workload
        self.thread = threading.Thread(target=self._simulate_workload, daemon=True)
        self.thread.start()

        print(f"  [OK] Pod {self.name} started on port {self.port}")

    def _simulate_workload(self):
        """Simulate pod workload"""
        while self.is_running:
            # Simulate resource usage
            self.cpu_usage = random.uniform(30, 70)
            self.memory_usage = random.uniform(1000, 3000)  # MB
            self.requests_handled += random.randint(10, 100)

            # Occasionally simulate errors
            if random.random() < 0.02:  # 2% error rate
                self.errors += 1

            time.sleep(1)

    def stop(self):
        """Stop the pod"""
        self.is_running = False
        self.status = "Terminated"

    def get_metrics(self) -> Dict:
        """Get pod metrics"""
        uptime = (datetime.now() - self.start_time).total_seconds()
        return {
            "name": self.name,
            "status": self.status,
            "cpu": f"{self.cpu_usage:.1f}%",
            "memory": f"{self.memory_usage:.0f}MB",
            "requests": self.requests_handled,
            "errors": self.errors,
            "uptime": f"{int(uptime)}s",
            "port": self.port
        }


class LocalKubernetesSimulator:
    """Simulates a local Kubernetes cluster"""

    def __init__(self):
        self.namespace = "catalytic-lattice"
        self.pods: List[Pod] = []
        self.services = {}
        self.is_running = False
        self.deployment_name = "catalytic-api"
        self.target_replicas = 3
        self.current_replicas = 0

    def create_namespace(self):
        """Simulate namespace creation"""
        print(f"\n[Creating Namespace]")
        print(f"  Creating namespace: {self.namespace}")
        time.sleep(1)
        print(f"  [OK] Namespace '{self.namespace}' created")

    def deploy_application(self, replicas: int = 3):
        """Simulate application deployment"""
        print(f"\n[Deploying Application]")
        print(f"  Deployment: {self.deployment_name}")
        print(f"  Target Replicas: {replicas}")

        self.target_replicas = replicas

        # Create pods
        for i in range(replicas):
            pod_name = f"{self.deployment_name}-{random.randint(1000, 9999)}"
            pod = Pod(pod_name, i)
            self.pods.append(pod)
            print(f"  Creating pod {i+1}/{replicas}: {pod_name}")
            pod.start()
            self.current_replicas += 1
            time.sleep(0.5)

        print(f"  [OK] All {replicas} pods are running")

    def create_service(self):
        """Simulate service creation"""
        print(f"\n[Creating Service]")
        print(f"  Service: {self.deployment_name}-service")
        print(f"  Type: LoadBalancer")
        print(f"  Port: 8080")

        self.services[f"{self.deployment_name}-service"] = {
            "type": "LoadBalancer",
            "port": 8080,
            "endpoints": [pod.port for pod in self.pods]
        }

        time.sleep(1)
        print(f"  [OK] Service created and endpoints configured")
        print(f"  [OK] LoadBalancer IP: localhost:8080 (simulated)")

    def setup_autoscaling(self):
        """Simulate HPA setup"""
        print(f"\n[Configuring Auto-scaling]")
        print(f"  HorizontalPodAutoscaler: {self.deployment_name}-hpa")
        print(f"  Min Replicas: 3")
        print(f"  Max Replicas: 20")
        print(f"  Target CPU: 70%")
        time.sleep(1)
        print(f"  [OK] Auto-scaling configured")

    def scale_deployment(self, new_replicas: int):
        """Scale the deployment"""
        print(f"\n[Scaling Deployment]")
        current = len(self.pods)

        if new_replicas > current:
            # Scale up
            print(f"  Scaling UP: {current} -> {new_replicas} replicas")
            for i in range(new_replicas - current):
                pod_name = f"{self.deployment_name}-{random.randint(1000, 9999)}"
                pod = Pod(pod_name, current + i)
                self.pods.append(pod)
                pod.start()

        elif new_replicas < current:
            # Scale down
            print(f"  Scaling DOWN: {current} -> {new_replicas} replicas")
            while len(self.pods) > new_replicas:
                pod = self.pods.pop()
                pod.stop()
                print(f"  [OK] Terminated pod: {pod.name}")

        self.current_replicas = new_replicas
        print(f"  [OK] Scaled to {new_replicas} replicas")

    def get_cluster_status(self) -> Dict:
        """Get cluster status"""
        total_cpu = sum(pod.cpu_usage for pod in self.pods if pod.status == "Running")
        total_memory = sum(pod.memory_usage for pod in self.pods if pod.status == "Running")
        total_requests = sum(pod.requests_handled for pod in self.pods)
        total_errors = sum(pod.errors for pod in self.pods)

        return {
            "namespace": self.namespace,
            "deployment": self.deployment_name,
            "ready_pods": len([p for p in self.pods if p.status == "Running"]),
            "total_pods": len(self.pods),
            "avg_cpu": total_cpu / len(self.pods) if self.pods else 0,
            "total_memory": total_memory,
            "total_requests": total_requests,
            "total_errors": total_errors,
            "error_rate": (total_errors / total_requests * 100) if total_requests > 0 else 0
        }

    def display_dashboard(self):
        """Display cluster dashboard"""
        while self.is_running:
            os.system('cls' if os.name == 'nt' else 'clear')

            print("=" * 70)
            print("  CATALYTIC LATTICE - LOCAL KUBERNETES DASHBOARD")
            print("=" * 70)
            print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
            print(f"  Namespace: {self.namespace}")
            print("=" * 70)

            # Cluster status
            status = self.get_cluster_status()
            print(f"\n[Cluster Status]")
            print(f"  Pods: {status['ready_pods']}/{status['total_pods']} Running")
            print(f"  CPU Usage: {status['avg_cpu']:.1f}%")
            print(f"  Memory: {status['total_memory']:.0f} MB")
            print(f"  Requests: {status['total_requests']}")
            print(f"  Error Rate: {status['error_rate']:.2f}%")

            # Pod details
            print(f"\n[Pod Status]")
            print(f"  {'Name':<30} {'Status':<10} {'CPU':<8} {'Memory':<10} {'Requests':<10}")
            print("  " + "-" * 66)

            for pod in self.pods[:5]:  # Show first 5 pods
                metrics = pod.get_metrics()
                print(f"  {metrics['name']:<30} {metrics['status']:<10} {metrics['cpu']:<8} "
                      f"{metrics['memory']:<10} {metrics['requests']:<10}")

            if len(self.pods) > 5:
                print(f"  ... and {len(self.pods) - 5} more pods")

            # Services
            print(f"\n[Services]")
            for name, service in self.services.items():
                print(f"  {name}: {service['type']} - Port {service['port']}")

            print(f"\n[Commands]")
            print(f"  [S] Scale deployment  [M] Monitor mode  [Q] Quit")
            print("=" * 70)

            time.sleep(3)

    def start_http_server(self):
        """Start a simple HTTP server to simulate the service"""
        class RequestHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = {
                        "status": "healthy",
                        "timestamp": datetime.now().isoformat(),
                        "service": "catalytic-api"
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    html = """
                    <html>
                    <head><title>Catalytic Lattice API</title></head>
                    <body>
                    <h1>Catalytic Lattice API - Local Deployment</h1>
                    <p>Service is running on STOOPIDPC</p>
                    <p>Endpoints:</p>
                    <ul>
                        <li><a href="/health">/health</a> - Health check</li>
                        <li>/api/* - API endpoints (simulated)</li>
                    </ul>
                    </body>
                    </html>
                    """
                    self.wfile.write(html.encode())

            def log_message(self, format, *args):
                pass  # Suppress log messages

        try:
            with socketserver.TCPServer(("", 8080), RequestHandler) as httpd:
                print(f"  [OK] HTTP server started on http://localhost:8080")
                httpd.serve_forever()
        except:
            print(f"  [WARN] Could not start HTTP server (port may be in use)")


def run_local_deployment():
    """Run the local deployment simulation"""

    print("\n" + "=" * 70)
    print("  LOCAL KUBERNETES DEPLOYMENT SIMULATOR")
    print("=" * 70)
    print("\nSimulating Kubernetes deployment on STOOPIDPC...")
    print("No Docker or Kubernetes installation required!")

    # Initialize simulator
    simulator = LocalKubernetesSimulator()
    simulator.is_running = True

    # Phase 1: Setup
    print("\n[PHASE 1: SETUP]")
    simulator.create_namespace()

    # Phase 2: Deployment
    print("\n[PHASE 2: DEPLOYMENT]")
    simulator.deploy_application(replicas=3)

    # Phase 3: Services
    print("\n[PHASE 3: SERVICES]")
    simulator.create_service()

    # Phase 4: Auto-scaling
    print("\n[PHASE 4: AUTO-SCALING]")
    simulator.setup_autoscaling()

    # Start HTTP server in background
    print("\n[PHASE 5: HTTP SERVICE]")
    http_thread = threading.Thread(
        target=simulator.start_http_server,
        daemon=True
    )
    http_thread.start()

    # Phase 6: Monitoring
    print("\n[PHASE 6: MONITORING]")
    print("  Starting dashboard...")
    time.sleep(2)

    # Interactive mode
    try:
        while True:
            simulator.display_dashboard()

            # Check for user input (with timeout)
            import select
            import sys

            if sys.platform == 'win32':
                # Windows doesn't support select on stdin
                time.sleep(3)
            else:
                # Unix/Linux/Mac
                ready = select.select([sys.stdin], [], [], 3)
                if ready[0]:
                    command = sys.stdin.readline().strip().lower()

                    if command == 's':
                        new_replicas = input("\nEnter new replica count (3-10): ")
                        try:
                            count = int(new_replicas)
                            if 3 <= count <= 10:
                                simulator.scale_deployment(count)
                                time.sleep(2)
                        except:
                            print("Invalid input")

                    elif command == 'q':
                        break

    except KeyboardInterrupt:
        pass

    print("\n\nShutting down local deployment...")
    simulator.is_running = False

    # Stop all pods
    for pod in simulator.pods:
        pod.stop()

    print("[OK] Local deployment stopped")
    print("\nSummary:")
    final_status = simulator.get_cluster_status()
    print(f"  Total Requests Handled: {final_status['total_requests']}")
    print(f"  Total Errors: {final_status['total_errors']}")
    print(f"  Average CPU Usage: {final_status['avg_cpu']:.1f}%")
    print(f"  Peak Memory: {final_status['total_memory']:.0f} MB")


if __name__ == "__main__":
    run_local_deployment()