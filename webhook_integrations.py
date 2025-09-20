"""
Webhook Integration Examples
Practical examples for integrating with GitHub, Docker, and Kubernetes
"""

import asyncio
import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional
import aiohttp
import yaml
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from github import Github
from docker import DockerClient
import docker.errors
from webhook_manager import WebhookManager, WebhookPriority

logger = logging.getLogger(__name__)

class GitHubIntegration:
    """GitHub webhook integration for CI/CD pipeline"""

    def __init__(self, webhook_manager: WebhookManager, github_token: str):
        self.webhook_manager = webhook_manager
        self.github = Github(github_token)

    async def setup_repository_webhooks(self, repo_name: str, webhook_url: str):
        """Setup webhooks for a GitHub repository"""
        try:
            repo = self.github.get_repo(repo_name)

            # Create webhook for push events
            hook_config = {
                "url": f"{webhook_url}/webhooks/github",
                "content_type": "json",
                "secret": os.getenv("GITHUB_WEBHOOK_SECRET", "your-secret")
            }

            events = ["push", "pull_request", "issues", "release", "deployment", "workflow_run"]

            hook = repo.create_hook(
                name="web",
                config=hook_config,
                events=events,
                active=True
            )

            logger.info(f"GitHub webhook created: {hook.id}")

            # Register internal webhook handlers
            await self._register_github_handlers()

            return hook.id

        except Exception as e:
            logger.error(f"Failed to setup GitHub webhook: {e}")
            raise

    async def _register_github_handlers(self):
        """Register internal handlers for GitHub events"""
        handlers = {
            "git.repository.push_to_main": self._handle_main_push,
            "git.repository.pull_request_opened": self._handle_pr_opened,
            "git.repository.security_scan_failed": self._handle_security_failure
        }

        for event, handler in handlers.items():
            # This would be integrated with your webhook manager
            logger.info(f"Registered handler for {event}")

    async def _handle_main_push(self, event_data: Dict[str, Any]):
        """Handle push to main branch"""
        commits = event_data.get("commits", [])

        # Trigger CI/CD pipeline
        pipeline_data = {
            "repository": event_data.get("repository", {}).get("name"),
            "branch": "main",
            "commits": commits,
            "pusher": event_data.get("pusher", {}).get("name")
        }

        # Trigger build
        await self.webhook_manager.trigger_event(
            "ci.pipeline.triggered",
            pipeline_data,
            priority=WebhookPriority.HIGH
        )

        # Run tests asynchronously
        asyncio.create_task(self._run_ci_pipeline(pipeline_data))

    async def _handle_pr_opened(self, event_data: Dict[str, Any]):
        """Handle new pull request"""
        pr_data = event_data.get("pull_request", {})

        # Automated PR checks
        checks = [
            self._check_pr_size(pr_data),
            self._check_pr_conflicts(pr_data),
            self._run_security_scan(pr_data)
        ]

        results = await asyncio.gather(*checks)

        # Post results as PR comment
        await self._post_pr_comment(pr_data, results)

    async def _handle_security_failure(self, event_data: Dict[str, Any]):
        """Handle security scan failures"""
        # Block deployment
        await self.webhook_manager.trigger_event(
            "deployment.blocked",
            {
                "reason": "security_scan_failed",
                "vulnerabilities": event_data.get("vulnerabilities", [])
            },
            priority=WebhookPriority.URGENT
        )

        # Notify security team
        await self._notify_security_team(event_data)

    async def _run_ci_pipeline(self, pipeline_data: Dict[str, Any]):
        """Run CI pipeline"""
        try:
            # Example: trigger GitHub Actions
            result = subprocess.run(
                ["gh", "workflow", "run", "ci.yml", "--ref", "main"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                await self.webhook_manager.trigger_event(
                    "ci.pipeline.succeeded",
                    pipeline_data,
                    priority=WebhookPriority.NORMAL
                )
            else:
                await self.webhook_manager.trigger_event(
                    "ci.pipeline.failed",
                    {"error": result.stderr, **pipeline_data},
                    priority=WebhookPriority.HIGH
                )

        except Exception as e:
            logger.error(f"CI pipeline error: {e}")

    async def _check_pr_size(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check PR size"""
        additions = pr_data.get("additions", 0)
        deletions = pr_data.get("deletions", 0)
        total_changes = additions + deletions

        return {
            "check": "pr_size",
            "passed": total_changes < 500,
            "message": f"PR contains {total_changes} changes"
        }

    async def _check_pr_conflicts(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check for merge conflicts"""
        mergeable = pr_data.get("mergeable", True)

        return {
            "check": "merge_conflicts",
            "passed": mergeable,
            "message": "No conflicts" if mergeable else "Merge conflicts detected"
        }

    async def _run_security_scan(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run security scan on PR"""
        # Placeholder for actual security scanning
        return {
            "check": "security_scan",
            "passed": True,
            "message": "Security scan passed"
        }

    async def _post_pr_comment(self, pr_data: Dict[str, Any], results: List[Dict[str, Any]]):
        """Post automated comment on PR"""
        comment_body = "## 🤖 Automated PR Review\n\n"

        for result in results:
            status = "✅" if result["passed"] else "❌"
            comment_body += f"{status} **{result['check']}**: {result['message']}\n"

        # This would post to GitHub
        logger.info(f"PR comment: {comment_body}")

    async def _notify_security_team(self, event_data: Dict[str, Any]):
        """Notify security team of vulnerabilities"""
        notification = {
            "severity": "critical",
            "vulnerabilities": event_data.get("vulnerabilities", []),
            "repository": event_data.get("repository")
        }

        await self.webhook_manager.trigger_event(
            "security.alert",
            notification,
            priority=WebhookPriority.URGENT
        )


class DockerIntegration:
    """Docker webhook integration for container management"""

    def __init__(self, webhook_manager: WebhookManager):
        self.webhook_manager = webhook_manager
        self.docker_client = DockerClient.from_env()
        self.monitoring_task: Optional[asyncio.Task] = None

    async def start_monitoring(self):
        """Start monitoring Docker events"""
        self.monitoring_task = asyncio.create_task(self._monitor_docker_events())
        logger.info("Docker monitoring started")

    async def stop_monitoring(self):
        """Stop monitoring Docker events"""
        if self.monitoring_task:
            self.monitoring_task.cancel()
            await asyncio.gather(self.monitoring_task, return_exceptions=True)

    async def _monitor_docker_events(self):
        """Monitor Docker daemon events"""
        try:
            for event in self.docker_client.events(decode=True):
                await self._process_docker_event(event)
        except Exception as e:
            logger.error(f"Docker monitoring error: {e}")

    async def _process_docker_event(self, event: Dict[str, Any]):
        """Process Docker event"""
        event_type = event.get("Type")
        action = event.get("Action")

        if event_type == "container":
            await self._handle_container_event(event, action)
        elif event_type == "image":
            await self._handle_image_event(event, action)
        elif event_type == "network":
            await self._handle_network_event(event, action)

    async def _handle_container_event(self, event: Dict[str, Any], action: str):
        """Handle container events"""
        container_id = event.get("Actor", {}).get("ID")
        container_name = event.get("Actor", {}).get("Attributes", {}).get("name")

        event_map = {
            "start": "docker.containers.container_started",
            "stop": "docker.containers.container_stopped",
            "die": "docker.containers.container_died",
            "health_status: unhealthy": "docker.containers.container_health_failed"
        }

        if action in event_map:
            await self.webhook_manager.trigger_event(
                event_map[action],
                {
                    "container_id": container_id,
                    "container_name": container_name,
                    "timestamp": event.get("time"),
                    "attributes": event.get("Actor", {}).get("Attributes", {})
                },
                priority=WebhookPriority.NORMAL if action != "die" else WebhookPriority.HIGH
            )

            # Additional actions based on event
            if action == "die":
                await self._handle_container_failure(container_id, container_name)

    async def _handle_container_failure(self, container_id: str, container_name: str):
        """Handle container failure"""
        try:
            # Get container details
            container = self.docker_client.containers.get(container_id)
            logs = container.logs(tail=100).decode('utf-8')

            # Check if it's a critical service
            labels = container.labels
            is_critical = labels.get("critical", "false") == "true"

            if is_critical:
                # Attempt automatic restart
                await self._restart_container(container)

                # Alert operations team
                await self.webhook_manager.trigger_event(
                    "operations.critical_failure",
                    {
                        "service": container_name,
                        "logs": logs,
                        "restart_attempted": True
                    },
                    priority=WebhookPriority.URGENT
                )

        except docker.errors.NotFound:
            logger.error(f"Container {container_id} not found")

    async def _restart_container(self, container):
        """Restart a failed container"""
        try:
            container.restart(timeout=30)
            logger.info(f"Container {container.name} restarted successfully")
        except Exception as e:
            logger.error(f"Failed to restart container: {e}")

    async def _handle_image_event(self, event: Dict[str, Any], action: str):
        """Handle Docker image events"""
        if action == "push":
            image_name = event.get("Actor", {}).get("Attributes", {}).get("name")

            await self.webhook_manager.trigger_event(
                "docker.registry.image_pushed",
                {
                    "image": image_name,
                    "timestamp": event.get("time")
                },
                priority=WebhookPriority.LOW
            )

            # Trigger security scan
            await self._scan_image(image_name)

    async def _scan_image(self, image_name: str):
        """Scan Docker image for vulnerabilities"""
        # Placeholder for actual scanning (e.g., using Trivy, Clair, etc.)
        scan_result = {
            "image": image_name,
            "vulnerabilities": [],
            "scan_time": "2024-01-01T00:00:00Z"
        }

        if scan_result["vulnerabilities"]:
            await self.webhook_manager.trigger_event(
                "security.image_vulnerability_found",
                scan_result,
                priority=WebhookPriority.HIGH
            )

    async def _handle_network_event(self, event: Dict[str, Any], action: str):
        """Handle Docker network events"""
        if action == "connect" or action == "disconnect":
            await self.webhook_manager.trigger_event(
                f"docker.network.{action}",
                {
                    "network": event.get("Actor", {}).get("Attributes", {}).get("name"),
                    "container": event.get("Actor", {}).get("Attributes", {}).get("container")
                },
                priority=WebhookPriority.LOW
            )


class KubernetesIntegration:
    """Kubernetes webhook integration for cluster management"""

    def __init__(self, webhook_manager: WebhookManager, kubeconfig_path: Optional[str] = None):
        self.webhook_manager = webhook_manager

        # Load Kubernetes configuration
        if kubeconfig_path:
            config.load_kube_config(config_file=kubeconfig_path)
        else:
            config.load_incluster_config()  # For running inside cluster

        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.watchers: List[asyncio.Task] = []

    async def start_watching(self, namespaces: List[str] = ["default"]):
        """Start watching Kubernetes resources"""
        for namespace in namespaces:
            # Watch pods
            pod_watcher = asyncio.create_task(
                self._watch_pods(namespace)
            )
            self.watchers.append(pod_watcher)

            # Watch deployments
            deployment_watcher = asyncio.create_task(
                self._watch_deployments(namespace)
            )
            self.watchers.append(deployment_watcher)

            # Watch services
            service_watcher = asyncio.create_task(
                self._watch_services(namespace)
            )
            self.watchers.append(service_watcher)

        logger.info(f"Started watching Kubernetes resources in namespaces: {namespaces}")

    async def stop_watching(self):
        """Stop watching Kubernetes resources"""
        for watcher in self.watchers:
            watcher.cancel()
        await asyncio.gather(*self.watchers, return_exceptions=True)

    async def _watch_pods(self, namespace: str):
        """Watch pod events"""
        w = watch.Watch()
        try:
            for event in w.stream(self.v1.list_namespaced_pod, namespace):
                await self._process_pod_event(event, namespace)
        except ApiException as e:
            logger.error(f"Error watching pods: {e}")

    async def _process_pod_event(self, event: Dict[str, Any], namespace: str):
        """Process pod event"""
        event_type = event['type']
        pod = event['object']

        event_map = {
            "ADDED": "deployment.kubernetes.pod_created",
            "MODIFIED": "deployment.kubernetes.pod_updated",
            "DELETED": "deployment.kubernetes.pod_terminated"
        }

        if event_type in event_map:
            pod_data = {
                "name": pod.metadata.name,
                "namespace": namespace,
                "labels": pod.metadata.labels,
                "phase": pod.status.phase if pod.status else "Unknown",
                "conditions": self._get_pod_conditions(pod),
                "containers": self._get_container_statuses(pod)
            }

            # Determine priority based on pod phase
            priority = WebhookPriority.NORMAL
            if pod.status and pod.status.phase in ["Failed", "Unknown"]:
                priority = WebhookPriority.HIGH

            await self.webhook_manager.trigger_event(
                event_map[event_type],
                pod_data,
                priority=priority
            )

            # Check for specific conditions
            if event_type == "MODIFIED":
                await self._check_pod_health(pod, namespace)

    async def _check_pod_health(self, pod, namespace: str):
        """Check pod health and trigger alerts"""
        if not pod.status:
            return

        # Check for restart loops
        for container_status in pod.status.container_statuses or []:
            if container_status.restart_count > 5:
                await self.webhook_manager.trigger_event(
                    "deployment.kubernetes.pod_restart_loop",
                    {
                        "pod": pod.metadata.name,
                        "namespace": namespace,
                        "container": container_status.name,
                        "restart_count": container_status.restart_count
                    },
                    priority=WebhookPriority.HIGH
                )

        # Check for OOM kills
        for container_status in pod.status.container_statuses or []:
            if container_status.last_state and container_status.last_state.terminated:
                if container_status.last_state.terminated.reason == "OOMKilled":
                    await self.webhook_manager.trigger_event(
                        "deployment.kubernetes.pod_oom_killed",
                        {
                            "pod": pod.metadata.name,
                            "namespace": namespace,
                            "container": container_status.name
                        },
                        priority=WebhookPriority.HIGH
                    )

    def _get_pod_conditions(self, pod) -> List[Dict[str, Any]]:
        """Extract pod conditions"""
        if not pod.status or not pod.status.conditions:
            return []

        return [
            {
                "type": condition.type,
                "status": condition.status,
                "reason": condition.reason,
                "message": condition.message
            }
            for condition in pod.status.conditions
        ]

    def _get_container_statuses(self, pod) -> List[Dict[str, Any]]:
        """Extract container statuses"""
        if not pod.status or not pod.status.container_statuses:
            return []

        return [
            {
                "name": status.name,
                "ready": status.ready,
                "restart_count": status.restart_count,
                "state": self._get_container_state(status.state)
            }
            for status in pod.status.container_statuses
        ]

    def _get_container_state(self, state) -> str:
        """Get container state as string"""
        if state.running:
            return "running"
        elif state.waiting:
            return f"waiting: {state.waiting.reason}"
        elif state.terminated:
            return f"terminated: {state.terminated.reason}"
        return "unknown"

    async def _watch_deployments(self, namespace: str):
        """Watch deployment events"""
        w = watch.Watch()
        try:
            for event in w.stream(self.apps_v1.list_namespaced_deployment, namespace):
                await self._process_deployment_event(event, namespace)
        except ApiException as e:
            logger.error(f"Error watching deployments: {e}")

    async def _process_deployment_event(self, event: Dict[str, Any], namespace: str):
        """Process deployment event"""
        event_type = event['type']
        deployment = event['object']

        if event_type == "MODIFIED":
            # Check for scaling events
            if hasattr(deployment.status, 'replicas'):
                current_replicas = deployment.status.replicas or 0
                desired_replicas = deployment.spec.replicas or 0

                if current_replicas != desired_replicas:
                    await self.webhook_manager.trigger_event(
                        "deployment.kubernetes.deployment_scaled",
                        {
                            "name": deployment.metadata.name,
                            "namespace": namespace,
                            "current_replicas": current_replicas,
                            "desired_replicas": desired_replicas
                        },
                        priority=WebhookPriority.NORMAL
                    )

    async def _watch_services(self, namespace: str):
        """Watch service events"""
        w = watch.Watch()
        try:
            for event in w.stream(self.v1.list_namespaced_service, namespace):
                await self._process_service_event(event, namespace)
        except ApiException as e:
            logger.error(f"Error watching services: {e}")

    async def _process_service_event(self, event: Dict[str, Any], namespace: str):
        """Process service event"""
        event_type = event['type']
        service = event['object']

        event_map = {
            "ADDED": "deployment.kubernetes.service_created",
            "MODIFIED": "deployment.kubernetes.service_updated",
            "DELETED": "deployment.kubernetes.service_deleted"
        }

        if event_type in event_map:
            service_data = {
                "name": service.metadata.name,
                "namespace": namespace,
                "type": service.spec.type,
                "cluster_ip": service.spec.cluster_ip,
                "ports": [
                    {
                        "name": port.name,
                        "port": port.port,
                        "target_port": port.target_port,
                        "protocol": port.protocol
                    }
                    for port in service.spec.ports or []
                ]
            }

            await self.webhook_manager.trigger_event(
                event_map[event_type],
                service_data,
                priority=WebhookPriority.LOW
            )


# Example usage
async def main():
    """Example usage of webhook integrations"""
    # Initialize webhook manager
    webhook_manager = WebhookManager("webhooks_config.yaml")
    await webhook_manager.start()

    # GitHub Integration
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        github_integration = GitHubIntegration(webhook_manager, github_token)
        await github_integration.setup_repository_webhooks(
            "your-org/your-repo",
            "https://your-webhook-endpoint.com"
        )

    # Docker Integration
    docker_integration = DockerIntegration(webhook_manager)
    await docker_integration.start_monitoring()

    # Kubernetes Integration
    k8s_integration = KubernetesIntegration(webhook_manager)
    await k8s_integration.start_watching(["default", "production"])

    # Let it run
    try:
        await asyncio.sleep(3600)  # Run for an hour
    finally:
        # Cleanup
        await docker_integration.stop_monitoring()
        await k8s_integration.stop_watching()
        await webhook_manager.stop()


if __name__ == "__main__":
    asyncio.run(main())