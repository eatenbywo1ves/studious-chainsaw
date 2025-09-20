"""
Webhook Router for Event Distribution
Routes events from various sources to the webhook manager
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import hmac
import hashlib
from datetime import datetime
from webhook_manager import WebhookManager, WebhookPriority

logger = logging.getLogger(__name__)

app = FastAPI(title="Webhook Router API", version="1.0.0")

# Global webhook manager instance
webhook_manager: Optional[WebhookManager] = None

class EventPayload(BaseModel):
    """Standard event payload"""
    event_type: str
    data: Dict[str, Any]
    source: str
    priority: str = "normal"

class GitHubWebhookPayload(BaseModel):
    """GitHub webhook payload"""
    action: str
    repository: Optional[Dict[str, Any]] = None
    pull_request: Optional[Dict[str, Any]] = None
    pusher: Optional[Dict[str, Any]] = None
    ref: Optional[str] = None
    commits: Optional[List[Dict[str, Any]]] = None

class DockerWebhookPayload(BaseModel):
    """Docker webhook payload"""
    events: List[Dict[str, Any]]
    push_data: Optional[Dict[str, Any]] = None
    repository: Optional[Dict[str, Any]] = None

class KubernetesEvent(BaseModel):
    """Kubernetes event payload"""
    type: str
    object: Dict[str, Any]
    old_object: Optional[Dict[str, Any]] = None

class PrometheusAlert(BaseModel):
    """Prometheus alert payload"""
    receiver: str
    status: str
    alerts: List[Dict[str, Any]]
    group_labels: Dict[str, str]
    common_labels: Dict[str, str]
    common_annotations: Dict[str, str]

@dataclass
class RouteHandler:
    """Route handler for specific event sources"""
    path: str
    handler: Callable
    verify_signature: bool = True
    signature_header: str = "X-Hub-Signature-256"
    secret_key: Optional[str] = None

class WebhookRouter:
    """Main webhook router class"""

    def __init__(self, webhook_manager: WebhookManager):
        self.webhook_manager = webhook_manager
        self.routes: Dict[str, RouteHandler] = {}
        self._setup_routes()

    def _setup_routes(self):
        """Setup route handlers for different sources"""
        self.routes = {
            "github": RouteHandler(
                path="/webhooks/github",
                handler=self._handle_github_webhook,
                verify_signature=True,
                signature_header="X-Hub-Signature-256",
                secret_key="github_webhook_secret"
            ),
            "docker": RouteHandler(
                path="/webhooks/docker",
                handler=self._handle_docker_webhook,
                verify_signature=False
            ),
            "kubernetes": RouteHandler(
                path="/webhooks/kubernetes",
                handler=self._handle_kubernetes_event,
                verify_signature=True,
                signature_header="X-Kubernetes-Signature"
            ),
            "prometheus": RouteHandler(
                path="/webhooks/prometheus",
                handler=self._handle_prometheus_alert,
                verify_signature=False
            ),
            "generic": RouteHandler(
                path="/webhooks/generic",
                handler=self._handle_generic_webhook,
                verify_signature=True,
                signature_header="X-Webhook-Signature"
            )
        }

    async def _handle_github_webhook(self, payload: GitHubWebhookPayload) -> Dict[str, Any]:
        """Handle GitHub webhooks"""
        event_mapping = {
            "push": "git.repository.push_to_main",
            "pull_request": "git.repository.pull_request_opened",
            "issues": "git.repository.issue_created",
            "release": "git.repository.release_published",
            "workflow_run": "git.ci.workflow_completed"
        }

        # Determine event type
        event_type = None
        if payload.ref and "main" in payload.ref:
            event_type = "git.repository.push_to_main"
        elif payload.pull_request:
            event_type = "git.repository.pull_request_opened"

        if event_type:
            await self.webhook_manager.trigger_event(
                event_type,
                payload.dict(),
                priority=WebhookPriority.NORMAL
            )

        return {"status": "processed", "event": event_type}

    async def _handle_docker_webhook(self, payload: DockerWebhookPayload) -> Dict[str, Any]:
        """Handle Docker registry webhooks"""
        events_processed = []

        for event in payload.events:
            event_type = event.get("action", "unknown")

            if event_type == "push":
                await self.webhook_manager.trigger_event(
                    "docker.containers.image_pushed",
                    {
                        "repository": payload.repository,
                        "tag": event.get("target", {}).get("tag"),
                        "digest": event.get("target", {}).get("digest")
                    },
                    priority=WebhookPriority.NORMAL
                )
            elif event_type == "pull":
                await self.webhook_manager.trigger_event(
                    "docker.containers.image_pulled",
                    event,
                    priority=WebhookPriority.LOW
                )

            events_processed.append(event_type)

        return {"status": "processed", "events": events_processed}

    async def _handle_kubernetes_event(self, payload: KubernetesEvent) -> Dict[str, Any]:
        """Handle Kubernetes events"""
        event_mapping = {
            "ADDED": {
                "Pod": "deployment.kubernetes.pod_created",
                "Service": "deployment.kubernetes.service_created",
                "Deployment": "deployment.kubernetes.deployment_created"
            },
            "MODIFIED": {
                "Pod": "deployment.kubernetes.pod_updated",
                "Service": "deployment.kubernetes.service_updated",
                "Deployment": "deployment.kubernetes.deployment_scaled"
            },
            "DELETED": {
                "Pod": "deployment.kubernetes.pod_terminated",
                "Service": "deployment.kubernetes.service_deleted",
                "Deployment": "deployment.kubernetes.deployment_deleted"
            }
        }

        obj_kind = payload.object.get("kind", "Unknown")
        event_type = event_mapping.get(payload.type, {}).get(obj_kind)

        if event_type:
            # Determine priority based on namespace
            namespace = payload.object.get("metadata", {}).get("namespace", "default")
            priority = WebhookPriority.HIGH if namespace == "production" else WebhookPriority.NORMAL

            await self.webhook_manager.trigger_event(
                event_type,
                {
                    "object": payload.object,
                    "old_object": payload.old_object,
                    "type": payload.type,
                    "namespace": namespace
                },
                priority=priority
            )

        return {"status": "processed", "event": event_type}

    async def _handle_prometheus_alert(self, payload: PrometheusAlert) -> Dict[str, Any]:
        """Handle Prometheus alerts"""
        alerts_processed = []

        for alert in payload.alerts:
            severity = alert.get("labels", {}).get("severity", "warning")

            # Map severity to priority
            priority_map = {
                "critical": WebhookPriority.URGENT,
                "error": WebhookPriority.HIGH,
                "warning": WebhookPriority.NORMAL,
                "info": WebhookPriority.LOW
            }

            priority = priority_map.get(severity, WebhookPriority.NORMAL)

            # Determine event type based on alert name
            alert_name = alert.get("labels", {}).get("alertname", "unknown")
            event_type = f"metrics.prometheus.{alert_name}"

            await self.webhook_manager.trigger_event(
                event_type,
                {
                    "alert": alert,
                    "status": payload.status,
                    "group_labels": payload.group_labels,
                    "annotations": alert.get("annotations", {})
                },
                priority=priority
            )

            alerts_processed.append(alert_name)

        return {"status": "processed", "alerts": alerts_processed}

    async def _handle_generic_webhook(self, payload: EventPayload) -> Dict[str, Any]:
        """Handle generic webhooks"""
        priority_map = {
            "urgent": WebhookPriority.URGENT,
            "high": WebhookPriority.HIGH,
            "normal": WebhookPriority.NORMAL,
            "low": WebhookPriority.LOW
        }

        priority = priority_map.get(payload.priority, WebhookPriority.NORMAL)

        await self.webhook_manager.trigger_event(
            payload.event_type,
            payload.data,
            priority=priority
        )

        return {"status": "processed", "event": payload.event_type}

    def verify_signature(self, payload: bytes, signature: str, secret: str,
                        algorithm: str = "sha256") -> bool:
        """Verify webhook signature"""
        if algorithm == "sha256":
            expected_signature = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()

            # GitHub format: sha256=signature
            if "=" in signature:
                _, signature = signature.split("=", 1)

            return hmac.compare_digest(expected_signature, signature)

        return False

# FastAPI Application Setup
@app.on_event("startup")
async def startup_event():
    """Initialize webhook manager on startup"""
    global webhook_manager
    webhook_manager = WebhookManager("webhooks_config.yaml")
    await webhook_manager.start()
    logger.info("Webhook Router started")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    if webhook_manager:
        await webhook_manager.stop()
    logger.info("Webhook Router stopped")

# API Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None)
):
    """GitHub webhook endpoint"""
    router = WebhookRouter(webhook_manager)

    # Verify signature if provided
    if x_hub_signature_256:
        body = await request.body()
        secret = "your_github_secret"  # Load from config
        if not router.verify_signature(body, x_hub_signature_256, secret):
            raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    result = await router._handle_github_webhook(GitHubWebhookPayload(**payload))

    return JSONResponse(content=result)

@app.post("/webhooks/docker")
async def docker_webhook(request: Request, background_tasks: BackgroundTasks):
    """Docker registry webhook endpoint"""
    router = WebhookRouter(webhook_manager)
    payload = await request.json()
    result = await router._handle_docker_webhook(DockerWebhookPayload(**payload))
    return JSONResponse(content=result)

@app.post("/webhooks/kubernetes")
async def kubernetes_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_kubernetes_signature: Optional[str] = Header(None)
):
    """Kubernetes webhook endpoint"""
    router = WebhookRouter(webhook_manager)

    # Verify signature if provided
    if x_kubernetes_signature:
        body = await request.body()
        secret = "your_k8s_secret"  # Load from config
        if not router.verify_signature(body, x_kubernetes_signature, secret):
            raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    result = await router._handle_kubernetes_event(KubernetesEvent(**payload))
    return JSONResponse(content=result)

@app.post("/webhooks/prometheus")
async def prometheus_webhook(request: Request, background_tasks: BackgroundTasks):
    """Prometheus Alertmanager webhook endpoint"""
    router = WebhookRouter(webhook_manager)
    payload = await request.json()
    result = await router._handle_prometheus_alert(PrometheusAlert(**payload))
    return JSONResponse(content=result)

@app.post("/webhooks/generic")
async def generic_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_webhook_signature: Optional[str] = Header(None)
):
    """Generic webhook endpoint"""
    router = WebhookRouter(webhook_manager)

    # Verify signature if provided
    if x_webhook_signature:
        body = await request.body()
        secret = "your_generic_secret"  # Load from config
        if not router.verify_signature(body, x_webhook_signature, secret):
            raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    result = await router._handle_generic_webhook(EventPayload(**payload))
    return JSONResponse(content=result)

@app.post("/webhooks/register")
async def register_webhook(
    event_name: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    secret: Optional[str] = None
):
    """Register a new webhook dynamically"""
    success = await webhook_manager.register_webhook(event_name, url, headers, secret)
    if success:
        return {"status": "registered", "event": event_name, "url": url}
    else:
        raise HTTPException(status_code=400, detail="Failed to register webhook")

@app.delete("/webhooks/unregister")
async def unregister_webhook(event_name: str, url: str):
    """Unregister a webhook"""
    success = await webhook_manager.unregister_webhook(event_name, url)
    if success:
        return {"status": "unregistered", "event": event_name, "url": url}
    else:
        raise HTTPException(status_code=404, detail="Webhook not found")

@app.get("/webhooks/list")
async def list_webhooks(event_name: Optional[str] = None):
    """List registered webhooks"""
    webhooks = await webhook_manager.list_webhooks(event_name)
    return {"webhooks": webhooks}

@app.get("/webhooks/metrics")
async def get_metrics():
    """Get webhook metrics"""
    metrics = await webhook_manager.get_metrics()
    return metrics

@app.post("/events/trigger")
async def trigger_event(event: EventPayload):
    """Manually trigger an event"""
    priority_map = {
        "urgent": WebhookPriority.URGENT,
        "high": WebhookPriority.HIGH,
        "normal": WebhookPriority.NORMAL,
        "low": WebhookPriority.LOW
    }

    priority = priority_map.get(event.priority, WebhookPriority.NORMAL)

    await webhook_manager.trigger_event(
        event.event_type,
        event.data,
        priority=priority
    )

    return {"status": "triggered", "event": event.event_type}

# Webhook receiver endpoints for testing
@app.post("/test/webhook/receiver")
async def test_webhook_receiver(request: Request):
    """Test webhook receiver endpoint"""
    headers = dict(request.headers)
    body = await request.json()

    logger.info(f"Test webhook received: {body}")

    return {
        "status": "received",
        "headers": headers,
        "body": body,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)