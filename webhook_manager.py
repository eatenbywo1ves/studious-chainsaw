"""
Advanced Webhook Manager for Catalytic Lattice System
Handles webhook registration, delivery, security, and retry logic
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import aiohttp
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, Gauge
import yaml
from asyncio import Queue
from collections import defaultdict
import jwt
import backoff

# Metrics
webhook_deliveries = Counter('webhook_deliveries_total', 'Total webhook deliveries', ['event', 'status'])
webhook_duration = Histogram('webhook_delivery_duration_seconds', 'Webhook delivery duration', ['event'])
webhook_queue_size = Gauge('webhook_queue_size', 'Current webhook queue size')
webhook_failures = Counter('webhook_failures_total', 'Total webhook failures', ['event', 'reason'])
circuit_breaker_state = Gauge('webhook_circuit_breaker_state', 'Circuit breaker state', ['url'])

logger = logging.getLogger(__name__)

class WebhookPriority(Enum):
    """Priority levels for webhook delivery"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4

class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = 0  # Normal operation
    OPEN = 1    # Blocking requests
    HALF_OPEN = 2  # Testing recovery

@dataclass
class WebhookPayload:
    """Webhook payload with metadata"""
    event_name: str
    event_data: Dict[str, Any]
    timestamp: float
    event_id: str
    priority: WebhookPriority = WebhookPriority.NORMAL
    retry_count: int = 0
    max_retries: int = 5
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WebhookEndpoint:
    """Webhook endpoint configuration"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    secret: Optional[str] = None
    timeout: int = 30
    retry_on: List[int] = field(default_factory=lambda: [500, 502, 503, 504])
    transform: Optional[str] = None
    active: bool = True

@dataclass
class CircuitBreaker:
    """Circuit breaker for webhook endpoints"""
    url: str
    failure_count: int = 0
    last_failure_time: Optional[float] = None
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    half_open_attempts: int = 0
    failure_threshold: int = 5
    timeout_seconds: int = 60
    half_open_max_attempts: int = 2

    def record_success(self):
        """Record successful request"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.half_open_attempts += 1
            if self.half_open_attempts >= self.half_open_max_attempts:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.half_open_attempts = 0
                logger.info(f"Circuit breaker CLOSED for {self.url}")
        else:
            self.failure_count = 0

    def record_failure(self):
        """Record failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning(f"Circuit breaker OPEN for {self.url}")

    def can_request(self) -> bool:
        """Check if request is allowed"""
        if self.state == CircuitBreakerState.CLOSED:
            return True

        if self.state == CircuitBreakerState.OPEN:
            if time.time() - self.last_failure_time > self.timeout_seconds:
                self.state = CircuitBreakerState.HALF_OPEN
                self.half_open_attempts = 0
                logger.info(f"Circuit breaker HALF_OPEN for {self.url}")
                return True
            return False

        return self.half_open_attempts < self.half_open_max_attempts

class WebhookManager:
    """Main webhook manager class"""

    def __init__(self, config_path: str, redis_url: str = "redis://localhost:6379"):
        self.config_path = config_path
        self.redis_url = redis_url
        self.config: Dict[str, Any] = {}
        self.endpoints: Dict[str, List[WebhookEndpoint]] = defaultdict(list)
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.delivery_queue: Queue = Queue()
        self.redis_client: Optional[redis.Redis] = None
        self.workers: List[asyncio.Task] = []
        self.running = False
        self._load_config()

    def _load_config(self):
        """Load webhook configuration from YAML"""
        with open(self.config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        # Parse webhook endpoints
        for category, events in self.config['webhooks']['events'].items():
            for event in events:
                event_name = f"{category}.{event['name']}"
                for webhook_config in event.get('webhooks', []):
                    endpoint = WebhookEndpoint(
                        url=webhook_config['url'],
                        method=webhook_config.get('method', 'POST'),
                        headers=webhook_config.get('headers', {}),
                        secret=webhook_config.get('secret_ref'),
                        timeout=webhook_config.get('timeout',
                                self.config['webhooks']['global']['timeout_seconds']),
                        retry_on=webhook_config.get('retry_on', [500, 502, 503, 504]),
                        transform=webhook_config.get('transform')
                    )
                    self.endpoints[event_name].append(endpoint)

    async def start(self):
        """Start the webhook manager"""
        self.running = True

        # Initialize Redis connection
        self.redis_client = await redis.from_url(self.redis_url)

        # Start delivery workers
        worker_count = self.config['webhooks']['delivery']['queue'].get('processing_workers', 5)
        for i in range(worker_count):
            worker = asyncio.create_task(self._delivery_worker(i))
            self.workers.append(worker)

        logger.info(f"Webhook manager started with {worker_count} workers")

    async def stop(self):
        """Stop the webhook manager"""
        self.running = False

        # Cancel all workers
        for worker in self.workers:
            worker.cancel()

        await asyncio.gather(*self.workers, return_exceptions=True)

        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()

        logger.info("Webhook manager stopped")

    async def trigger_event(self, event_name: str, event_data: Dict[str, Any],
                           priority: WebhookPriority = WebhookPriority.NORMAL):
        """Trigger a webhook event"""
        if event_name not in self.endpoints:
            logger.warning(f"No webhooks configured for event: {event_name}")
            return

        # Create payload
        payload = WebhookPayload(
            event_name=event_name,
            event_data=event_data,
            timestamp=time.time(),
            event_id=self._generate_event_id(),
            priority=priority
        )

        # Queue for delivery
        await self.delivery_queue.put((priority.value, payload))
        webhook_queue_size.set(self.delivery_queue.qsize())

        logger.info(f"Event queued: {event_name} with priority {priority.name}")

    async def _delivery_worker(self, worker_id: int):
        """Worker to process webhook deliveries"""
        logger.info(f"Delivery worker {worker_id} started")

        while self.running:
            try:
                # Get item from queue (priority-based)
                priority, payload = await asyncio.wait_for(
                    self.delivery_queue.get(), timeout=1.0
                )
                webhook_queue_size.set(self.delivery_queue.qsize())

                # Deliver to all endpoints
                endpoints = self.endpoints.get(payload.event_name, [])
                delivery_tasks = []

                for endpoint in endpoints:
                    if endpoint.active:
                        task = self._deliver_webhook(payload, endpoint)
                        delivery_tasks.append(task)

                # Execute deliveries in parallel
                await asyncio.gather(*delivery_tasks, return_exceptions=True)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")

    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, asyncio.TimeoutError),
        max_tries=5,
        max_time=300
    )
    async def _deliver_webhook(self, payload: WebhookPayload, endpoint: WebhookEndpoint):
        """Deliver webhook to an endpoint with retries"""
        start_time = time.time()

        # Check circuit breaker
        circuit_breaker = self._get_circuit_breaker(endpoint.url)
        if not circuit_breaker.can_request():
            logger.warning(f"Circuit breaker preventing delivery to {endpoint.url}")
            webhook_failures.labels(event=payload.event_name, reason='circuit_breaker').inc()
            return

        try:
            # Prepare payload
            webhook_data = await self._prepare_payload(payload, endpoint)

            # Add security headers
            headers = endpoint.headers.copy()
            if self.config['webhooks']['security']['signing']['enabled']:
                signature = self._generate_signature(webhook_data, endpoint.secret)
                headers[self.config['webhooks']['security']['signing']['header_name']] = signature
                headers[self.config['webhooks']['security']['signing']['timestamp_header']] = str(int(payload.timestamp))

            # Make HTTP request
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    json=webhook_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=endpoint.timeout)
                ) as response:

                    # Check response status
                    if response.status >= 400:
                        if response.status in endpoint.retry_on:
                            raise aiohttp.ClientError(f"Retryable error: {response.status}")
                        else:
                            logger.error(f"Non-retryable error {response.status} for {endpoint.url}")

                    # Record success
                    circuit_breaker.record_success()
                    webhook_deliveries.labels(event=payload.event_name, status='success').inc()
                    webhook_duration.labels(event=payload.event_name).observe(time.time() - start_time)

                    logger.info(f"Webhook delivered successfully to {endpoint.url}")

        except Exception as e:
            # Record failure
            circuit_breaker.record_failure()
            webhook_failures.labels(event=payload.event_name, reason=type(e).__name__).inc()

            # Store in dead letter queue if max retries exceeded
            if payload.retry_count >= payload.max_retries:
                await self._store_dead_letter(payload, endpoint, str(e))

            logger.error(f"Webhook delivery failed to {endpoint.url}: {e}")
            raise

    async def _prepare_payload(self, payload: WebhookPayload, endpoint: WebhookEndpoint) -> Dict[str, Any]:
        """Prepare webhook payload with transformations"""
        base_payload = {
            "event": payload.event_name,
            "timestamp": payload.timestamp,
            "event_id": payload.event_id,
            "data": payload.event_data
        }

        # Apply transformer if specified
        if endpoint.transform and endpoint.transform in self.config['webhooks']['transformers']:
            transformer = self.config['webhooks']['transformers'][endpoint.transform]
            if transformer['type'] == 'template':
                # Apply template transformation
                from jinja2 import Template
                template = Template(transformer['template'])
                transformed = template.render(
                    event_name=payload.event_name,
                    **payload.event_data
                )
                return json.loads(transformed)

        return base_payload

    def _generate_signature(self, data: Dict[str, Any], secret: Optional[str]) -> str:
        """Generate HMAC signature for webhook payload"""
        if not secret:
            secret = self.config['webhooks']['security'].get('default_secret', 'default-secret')

        message = json.dumps(data, sort_keys=True)
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"sha256={signature}"

    def _get_circuit_breaker(self, url: str) -> CircuitBreaker:
        """Get or create circuit breaker for URL"""
        if url not in self.circuit_breakers:
            cb_config = self.config['webhooks']['delivery']['circuit_breaker']
            self.circuit_breakers[url] = CircuitBreaker(
                url=url,
                failure_threshold=cb_config['failure_threshold'],
                timeout_seconds=cb_config['timeout_seconds'],
                half_open_max_attempts=cb_config['half_open_requests']
            )
        return self.circuit_breakers[url]

    async def _store_dead_letter(self, payload: WebhookPayload, endpoint: WebhookEndpoint, error: str):
        """Store failed webhook in dead letter queue"""
        dead_letter_data = {
            "payload": {
                "event_name": payload.event_name,
                "event_data": payload.event_data,
                "timestamp": payload.timestamp,
                "event_id": payload.event_id
            },
            "endpoint": {
                "url": endpoint.url,
                "method": endpoint.method
            },
            "error": error,
            "stored_at": time.time()
        }

        # Store in Redis with expiry
        if self.redis_client:
            key = f"webhook:dead_letter:{payload.event_id}"
            retention_days = self.config['webhooks']['delivery']['dead_letter']['retention_days']
            await self.redis_client.setex(
                key,
                timedelta(days=retention_days),
                json.dumps(dead_letter_data)
            )

            logger.warning(f"Webhook stored in dead letter queue: {key}")

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import uuid
        return str(uuid.uuid4())

    async def register_webhook(self, event_name: str, url: str,
                              headers: Optional[Dict[str, str]] = None,
                              secret: Optional[str] = None) -> bool:
        """Dynamically register a new webhook"""
        endpoint = WebhookEndpoint(
            url=url,
            headers=headers or {},
            secret=secret
        )

        self.endpoints[event_name].append(endpoint)

        # Persist to Redis
        if self.redis_client:
            key = f"webhook:registration:{event_name}:{url}"
            await self.redis_client.set(key, json.dumps({
                "url": url,
                "headers": headers,
                "registered_at": time.time()
            }))

        logger.info(f"Webhook registered: {event_name} -> {url}")
        return True

    async def unregister_webhook(self, event_name: str, url: str) -> bool:
        """Unregister a webhook"""
        if event_name in self.endpoints:
            self.endpoints[event_name] = [
                ep for ep in self.endpoints[event_name]
                if ep.url != url
            ]

            # Remove from Redis
            if self.redis_client:
                key = f"webhook:registration:{event_name}:{url}"
                await self.redis_client.delete(key)

            logger.info(f"Webhook unregistered: {event_name} -> {url}")
            return True

        return False

    async def list_webhooks(self, event_name: Optional[str] = None) -> Dict[str, List[str]]:
        """List registered webhooks"""
        if event_name:
            return {
                event_name: [ep.url for ep in self.endpoints.get(event_name, [])]
            }

        return {
            event: [ep.url for ep in endpoints]
            for event, endpoints in self.endpoints.items()
        }

    async def get_metrics(self) -> Dict[str, Any]:
        """Get webhook metrics"""
        metrics = {
            "queue_size": self.delivery_queue.qsize(),
            "circuit_breakers": {
                url: {
                    "state": cb.state.name,
                    "failure_count": cb.failure_count
                }
                for url, cb in self.circuit_breakers.items()
            },
            "endpoints": {
                event: len(endpoints)
                for event, endpoints in self.endpoints.items()
            }
        }

        return metrics


# Example usage
async def main():
    """Example usage of WebhookManager"""
    manager = WebhookManager("webhooks_config.yaml")
    await manager.start()

    # Trigger some events
    await manager.trigger_event(
        "system.health.health_check_failed",
        {"service": "api", "status": "unhealthy", "details": "Connection timeout"},
        priority=WebhookPriority.HIGH
    )

    await manager.trigger_event(
        "deployment.kubernetes.pod_created",
        {"pod_name": "api-server-abc123", "namespace": "production"},
        priority=WebhookPriority.NORMAL
    )

    # Let it run for a bit
    await asyncio.sleep(10)

    # Get metrics
    metrics = await manager.get_metrics()
    print(f"Metrics: {json.dumps(metrics, indent=2)}")

    await manager.stop()

if __name__ == "__main__":
    asyncio.run(main())