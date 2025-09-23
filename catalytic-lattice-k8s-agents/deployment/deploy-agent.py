#!/usr/bin/env python3
"""
Deployment Agent for Catalytic Lattice API Service
Handles automated deployment to Kubernetes clusters (K8s, EKS, AKS, GKE)
"""

import subprocess
import json
import sys
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class CloudProvider(Enum):
    LOCAL = "local"
    GKE = "gke"
    EKS = "eks"
    AKS = "aks"


@dataclass
class DeploymentConfig:
    provider: CloudProvider
    cluster_name: str
    namespace: str = "catalytic-lattice"
    replicas: int = 3
    cpu_limit: str = "32"
    memory_limit: str = "64Gi"
    auto_scale: bool = True
    min_replicas: int = 3
    max_replicas: int = 20
    target_cpu: int = 80


class DeploymentAgent:
    def __init__(self, config: DeploymentConfig):
        self.config = config
        self.kubectl_cmd = self._get_kubectl_command()

    def _get_kubectl_command(self) -> str:
        """Get the appropriate kubectl command based on environment"""
        if os.name == 'nt':  # Windows
            return "kubectl"
        return "kubectl"

    def _run_command(self, cmd: List[str]) -> Dict:
        """Execute shell command and return result"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=(os.name == 'nt')
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e)
            }

    def check_prerequisites(self) -> bool:
        """Verify all prerequisites are met"""
        checks = []

        # Check kubectl
        result = self._run_command([self.kubectl_cmd, "version", "--client"])
        checks.append(("kubectl", result["success"]))

        # Check Docker
        docker_cmd = "docker" if os.name != 'nt' else "docker"
        result = self._run_command([docker_cmd, "version"])
        checks.append(("docker", result["success"]))

        # Check cloud CLI based on provider
        if self.config.provider == CloudProvider.GKE:
            result = self._run_command(["gcloud", "version"])
            checks.append(("gcloud", result["success"]))
        elif self.config.provider == CloudProvider.EKS:
            result = self._run_command(["aws", "--version"])
            checks.append(("aws-cli", result["success"]))
        elif self.config.provider == CloudProvider.AKS:
            result = self._run_command(["az", "--version"])
            checks.append(("azure-cli", result["success"]))

        print("Prerequisites Check:")
        for tool, status in checks:
            status_str = "[OK]" if status else "[FAIL]"
            print(f"  {status_str} {tool}")

        return all(status for _, status in checks)

    def setup_cluster_credentials(self) -> bool:
        """Configure kubectl to connect to the cluster"""
        print(f"\nSetting up credentials for {self.config.provider.value} cluster...")

        if self.config.provider == CloudProvider.LOCAL:
            # For local development (Docker Desktop/Minikube)
            print("Using local Kubernetes context")
            return True

        elif self.config.provider == CloudProvider.GKE:
            cmd = [
                "gcloud", "container", "clusters",
                "get-credentials", self.config.cluster_name
            ]

        elif self.config.provider == CloudProvider.EKS:
            cmd = [
                "aws", "eks", "update-kubeconfig",
                "--name", self.config.cluster_name
            ]

        elif self.config.provider == CloudProvider.AKS:
            cmd = [
                "az", "aks", "get-credentials",
                "--name", self.config.cluster_name,
                "--resource-group", "my-rg"  # Should be parameterized
            ]

        result = self._run_command(cmd)
        if result["success"]:
            print("[OK] Cluster credentials configured")
        else:
            print(f"[FAIL] Failed to configure credentials: {result['error']}")

        return result["success"]

    def create_namespace(self) -> bool:
        """Create Kubernetes namespace if it doesn't exist"""
        print(f"\nCreating namespace: {self.config.namespace}")

        # Check if namespace exists
        cmd = [self.kubectl_cmd, "get", "namespace", self.config.namespace]
        result = self._run_command(cmd)

        if result["success"]:
            print(f"  Namespace {self.config.namespace} already exists")
            return True

        # Create namespace
        cmd = [self.kubectl_cmd, "create", "namespace", self.config.namespace]
        result = self._run_command(cmd)

        if result["success"]:
            print(f"[OK] Namespace {self.config.namespace} created")
        else:
            print(f"[FAIL] Failed to create namespace: {result['error']}")

        return result["success"]

    def deploy_application(self) -> bool:
        """Deploy the Catalytic Lattice API application"""
        print("\nDeploying Catalytic Lattice API...")

        # Generate deployment manifest
        manifest = self._generate_deployment_manifest()

        # Apply deployment
        with open("/tmp/deployment.yaml", "w") as f:
            f.write(manifest)

        cmd = [
            self.kubectl_cmd, "apply",
            "-f", "/tmp/deployment.yaml",
            "-n", self.config.namespace
        ]

        result = self._run_command(cmd)

        if result["success"]:
            print("[OK] Deployment applied successfully")
        else:
            print(f"[FAIL] Deployment failed: {result['error']}")

        return result["success"]

    def _generate_deployment_manifest(self) -> str:
        """Generate Kubernetes deployment manifest"""
        return f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catalytic-api
  namespace: {self.config.namespace}
spec:
  replicas: {self.config.replicas}
  selector:
    matchLabels:
      app: catalytic-api
  template:
    metadata:
      labels:
        app: catalytic-api
    spec:
      containers:
      - name: api
        image: catalytic/api:latest
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: "{self.config.cpu_limit}"
            memory: {self.config.memory_limit}
          requests:
            cpu: "2"
            memory: "4Gi"
        env:
        - name: NODE_ENV
          value: production
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: catalytic-api-service
  namespace: {self.config.namespace}
spec:
  selector:
    app: catalytic-api
  ports:
  - port: 8080
    targetPort: 8080
  type: LoadBalancer
"""

    def setup_autoscaling(self) -> bool:
        """Configure horizontal pod autoscaling"""
        if not self.config.auto_scale:
            print("Autoscaling disabled in configuration")
            return True

        print("\nConfiguring autoscaling...")

        cmd = [
            self.kubectl_cmd, "autoscale", "deployment",
            "catalytic-api",
            f"--min={self.config.min_replicas}",
            f"--max={self.config.max_replicas}",
            f"--cpu-percent={self.config.target_cpu}",
            "-n", self.config.namespace
        ]

        result = self._run_command(cmd)

        if result["success"]:
            print(f"[OK] Autoscaling configured: {self.config.min_replicas}-{self.config.max_replicas} replicas")
        else:
            print(f"[FAIL] Failed to configure autoscaling: {result['error']}")

        return result["success"]

    def verify_deployment(self) -> bool:
        """Verify deployment status"""
        print("\nVerifying deployment...")

        # Check deployment status
        cmd = [
            self.kubectl_cmd, "get", "deployment",
            "catalytic-api",
            "-n", self.config.namespace,
            "-o", "json"
        ]

        result = self._run_command(cmd)

        if not result["success"]:
            print("[FAIL] Failed to get deployment status")
            return False

        try:
            deployment = json.loads(result["output"])
            ready_replicas = deployment["status"].get("readyReplicas", 0)
            desired_replicas = deployment["spec"]["replicas"]

            if ready_replicas == desired_replicas:
                print(f"[OK] All {ready_replicas}/{desired_replicas} replicas are ready")
                return True
            else:
                print(f"[WAITING] {ready_replicas}/{desired_replicas} replicas ready")
                return False
        except Exception as e:
            print(f"[FAIL] Error parsing deployment status: {e}")
            return False

    def get_service_endpoint(self) -> Optional[str]:
        """Get the service endpoint URL"""
        cmd = [
            self.kubectl_cmd, "get", "service",
            "catalytic-api-service",
            "-n", self.config.namespace,
            "-o", "json"
        ]

        result = self._run_command(cmd)

        if not result["success"]:
            return None

        try:
            service = json.loads(result["output"])

            # For LoadBalancer type
            if service["spec"]["type"] == "LoadBalancer":
                ingress = service["status"].get("loadBalancer", {}).get("ingress", [])
                if ingress:
                    host = ingress[0].get("ip") or ingress[0].get("hostname")
                    port = service["spec"]["ports"][0]["port"]
                    return f"http://{host}:{port}"

            # For NodePort or ClusterIP
            port = service["spec"]["ports"][0].get("nodePort") or service["spec"]["ports"][0]["port"]
            return f"http://localhost:{port}"

        except Exception as e:
            print(f"Error getting service endpoint: {e}")
            return None

    def deploy(self) -> bool:
        """Execute full deployment pipeline"""
        print(f"Starting deployment to {self.config.provider.value}")
        print("=" * 50)

        steps = [
            ("Checking prerequisites", self.check_prerequisites),
            ("Setting up cluster credentials", self.setup_cluster_credentials),
            ("Creating namespace", self.create_namespace),
            ("Deploying application", self.deploy_application),
            ("Setting up autoscaling", self.setup_autoscaling),
            ("Verifying deployment", self.verify_deployment)
        ]

        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            if not step_func():
                print(f"\n[ERROR] Deployment failed at: {step_name}")
                return False

        print("\n" + "=" * 50)
        print("[SUCCESS] Deployment completed successfully!")

        endpoint = self.get_service_endpoint()
        if endpoint:
            print(f"\n[READY] Service available at: {endpoint}")

        return True


def main():
    """Main entry point"""
    # Parse command line arguments or use defaults
    provider = CloudProvider.LOCAL
    if len(sys.argv) > 1:
        provider_str = sys.argv[1].lower()
        if provider_str in ["gke", "eks", "aks"]:
            provider = CloudProvider[provider_str.upper()]

    config = DeploymentConfig(
        provider=provider,
        cluster_name="my-cluster" if provider != CloudProvider.LOCAL else "docker-desktop",
        namespace="catalytic-lattice",
        replicas=3,
        auto_scale=True
    )

    agent = DeploymentAgent(config)

    if not agent.deploy():
        sys.exit(1)


if __name__ == "__main__":
    main()