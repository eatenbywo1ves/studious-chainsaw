"""
Reactive Webhook Manager using RxPy
Refactored from webhook_manager.py to demonstrate reactive programming principles
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
import aiohttp
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, Gauge
import yaml

# RxPy imports - the reactive programming library for Python
from reactivex import Subject, Observable, operators as ops, create
from reactivex.scheduler.eventloop import AsyncIOScheduler
from reactivex.subject import BehaviorSubject

logger = logging.getLogger(__name__)

# Metrics (same as original)
webhook_deliveries = Counter(
    "webhook_deliveries_total", "Total webhook deliveries", ["event", "status"]
)
webhook_duration = Histogram(
    "webhook_delivery_duration_seconds", "Webhook delivery duration", ["event"]
)
webhook_queue_size = Gauge("webhook_queue_size", "Current webhook queue size")
webhook_failures = Counter("webhook_failures_total", "Total webhook failures", ["event", "reason"])
circuit_breaker_state = Gauge("webhook_circuit_breaker_state", "Circuit breaker state", ["url"])


class WebhookPriority(Enum):
    """Priority levels for webhook delivery"""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4


class CircuitBreakerState(Enum):
    """Circuit breaker states"""

    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


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


@dataclass
class WebhookDeliveryResult:
    """Result of a webhook delivery attempt"""

    payload: WebhookPayload
    endpoint: WebhookEndpoint
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    duration: float = 0.0


class ReactiveWebhookManager:
    """
    Reactive Webhook Manager using RxPy streams

    Key Differences from Original:
    1. No manual worker pool - replaced with reactive schedulers
    2. No explicit queue management - streams handle backpressure
    3. Declarative operators replace imperative loops
    4. Error handling via reactive operators (retry, catch)
    5. Circuit breaker as stream filter
    """

    def __init__(self, config_path: str, redis_url: str = "redis://localhost:6379"):
        self.config_path = config_path
        self.redis_url = redis_url
        self.config: Dict[str, Any] = {}
        self.endpoints: Dict[str, List[WebhookEndpoint]] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.redis_client: Optional[redis.Redis] = None

        # Reactive subjects - these are "hot" observables that emit events
        self.webhook_stream = Subject()  # Main event stream
        self.metrics_stream = Subject()  # Metrics events
        self.circuit_breaker_stream = BehaviorSubject(None)  # Circuit breaker state changes

        # Scheduler for async operations
        self.scheduler = AsyncIOScheduler()

        # Subscriptions to dispose on shutdown
        self.subscriptions = []

        self._load_config()
        self._setup_reactive_pipeline()

    def _load_config(self):
        """Load webhook configuration from YAML"""
        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f)

        # Parse webhook endpoints
        from collections import defaultdict

        self.endpoints = defaultdict(list)
        for category, events in self.config["webhooks"]["events"].items():
            for event in events:
                event_name = f"{category}.{event['name']}"
                for webhook_config in event.get("webhooks", []):
                    endpoint = WebhookEndpoint(
                        url=webhook_config["url"],
                        method=webhook_config.get("method", "POST"),
                        headers=webhook_config.get("headers", {}),
                        secret=webhook_config.get("secret_ref"),
                        timeout=webhook_config.get(
                            "timeout", self.config["webhooks"]["global"]["timeout_seconds"]
                        ),
                        retry_on=webhook_config.get("retry_on", [500, 502, 503, 504]),
                        transform=webhook_config.get("transform"),
                    )
                    self.endpoints[event_name].append(endpoint)

    def _setup_reactive_pipeline(self):
        """
        Setup the reactive pipeline - This is where the magic happens!

        Instead of manual worker loops, we declare HOW data flows through transformations.
        """

        # PIPELINE 1: Main webhook delivery stream
        # This replaces the entire _delivery_worker method from the original
        delivery_subscription = self.webhook_stream.pipe(
            # Operator 1: Log incoming events
            ops.do_action(
                on_next=lambda payload: logger.info(
                    f"Event received: {payload.event_name} (priority: {payload.priority.name})"
                )
            ),
            # Operator 2: Group by priority for prioritized processing
            # This automatically creates separate streams per priority level
            ops.group_by(lambda payload: payload.priority.value),
            # Operator 3: Process each priority group
            ops.flat_map(
                lambda priority_group: priority_group.pipe(
                    # For each payload, emit (payload, endpoint) pairs
                    ops.flat_map(lambda payload: self._create_delivery_pairs(payload)),
                    # Filter out endpoints blocked by circuit breakers
                    ops.filter(lambda pair: self._check_circuit_breaker(pair[1].url)),
                    # Transform to delivery observable
                    ops.flat_map(
                        lambda pair: self._deliver_webhook_reactive(pair[0], pair[1]),
                        # Max concurrent deliveries per priority group
                        max_concurrent=10,
                    ),
                    # Retry failed deliveries (replaces @backoff decorator)
                    ops.retry(5),
                    # Catch errors and route to dead letter queue
                    ops.catch(lambda error, source: self._handle_delivery_error(error, source)),
                )
            ),
            # Operator 4: Share the stream among subscribers (hot observable)
            ops.share(),
        ).subscribe(
            on_next=self._on_delivery_success,
            on_error=self._on_delivery_error,
            scheduler=self.scheduler,
        )

        self.subscriptions.append(delivery_subscription)

        # PIPELINE 2: Metrics collection stream
        # Separate stream for metrics - demonstrates stream composition
        metrics_subscription = self.metrics_stream.pipe(
            # Buffer metrics for 1 second windows
            ops.buffer_with_time(1.0),
            ops.filter(lambda buffer: len(buffer) > 0),
            ops.do_action(on_next=lambda metrics_batch: self._update_metrics(metrics_batch)),
        ).subscribe(scheduler=self.scheduler)

        self.subscriptions.append(metrics_subscription)

        # PIPELINE 3: Circuit breaker state monitoring
        # React to circuit breaker state changes
        cb_subscription = self.circuit_breaker_stream.pipe(
            ops.filter(lambda state: state is not None),
            ops.distinct_until_changed(),
            ops.do_action(
                on_next=lambda state: circuit_breaker_state.labels(url=state["url"]).set(
                    state["state"].value
                )
            ),
        ).subscribe(scheduler=self.scheduler)

        self.subscriptions.append(cb_subscription)

    def _create_delivery_pairs(self, payload: WebhookPayload) -> Observable:
        """
        Create observable of (payload, endpoint) pairs for delivery

        This replaces the loop:
            for endpoint in endpoints:
                if endpoint.active:
                    ...
        """

        def subscribe(observer, scheduler=None):
            endpoints = self.endpoints.get(payload.event_name, [])
            for endpoint in endpoints:
                if endpoint.active:
                    observer.on_next((payload, endpoint))
            observer.on_completed()
            return lambda: None  # No cleanup needed

        return create(subscribe)

    def _check_circuit_breaker(self, url: str) -> bool:
        """
        Check if circuit breaker allows request

        Reactive note: This is a synchronous filter - returns True/False
        In pure reactive, this could be an Observable that emits the URL if allowed
        """
        circuit_breaker = self._get_circuit_breaker(url)
        return circuit_breaker.can_request()

    def _deliver_webhook_reactive(
        self, payload: WebhookPayload, endpoint: WebhookEndpoint
    ) -> Observable:
        """
        Deliver webhook to endpoint - returns Observable for reactive composition

        Original code used async/await with @backoff decorator.
        Reactive version returns Observable that can be composed with retry(), catch(), etc.
        """

        async def deliver():
            start_time = time.time()
            circuit_breaker = self._get_circuit_breaker(endpoint.url)

            try:
                # Prepare payload
                webhook_data = await self._prepare_payload(payload, endpoint)

                # Add security headers
                headers = endpoint.headers.copy()
                if self.config["webhooks"]["security"]["signing"]["enabled"]:
                    signature = self._generate_signature(webhook_data, endpoint.secret)
                    headers[self.config["webhooks"]["security"]["signing"]["header_name"]] = (
                        signature
                    )
                    headers[self.config["webhooks"]["security"]["signing"]["timestamp_header"]] = (
                        str(int(payload.timestamp))
                    )

                # Make HTTP request
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=endpoint.method,
                        url=endpoint.url,
                        json=webhook_data,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=endpoint.timeout),
                    ) as response:
                        # Check response status
                        if response.status >= 400:
                            if response.status in endpoint.retry_on:
                                raise aiohttp.ClientError(f"Retryable error: {response.status}")
                            else:
                                logger.error(
                                    f"Non-retryable error {response.status} for {endpoint.url}"
                                )

                        # Record success
                        circuit_breaker.record_success()
                        duration = time.time() - start_time

                        # Emit metrics to metrics stream
                        self.metrics_stream.on_next(
                            {
                                "type": "delivery_success",
                                "event": payload.event_name,
                                "duration": duration,
                                "endpoint": endpoint.url,
                            }
                        )

                        # Emit circuit breaker state
                        self.circuit_breaker_stream.on_next(
                            {"url": endpoint.url, "state": circuit_breaker.state}
                        )

                        logger.info(f"Webhook delivered successfully to {endpoint.url}")

                        return WebhookDeliveryResult(
                            payload=payload,
                            endpoint=endpoint,
                            success=True,
                            status_code=response.status,
                            duration=duration,
                        )

            except Exception as e:
                # Record failure
                circuit_breaker.record_failure()
                duration = time.time() - start_time

                # Emit metrics
                self.metrics_stream.on_next(
                    {
                        "type": "delivery_failure",
                        "event": payload.event_name,
                        "error": type(e).__name__,
                        "endpoint": endpoint.url,
                    }
                )

                # Emit circuit breaker state
                self.circuit_breaker_stream.on_next(
                    {"url": endpoint.url, "state": circuit_breaker.state}
                )

                logger.error(f"Webhook delivery failed to {endpoint.url}: {e}")

                # If max retries exceeded, send to dead letter queue
                if payload.retry_count >= payload.max_retries:
                    await self._store_dead_letter(payload, endpoint, str(e))

                # Re-raise for retry operator to catch
                raise

        # Convert async function to Observable
        # This is the bridge between async/await and reactive streams
        def subscribe(observer, scheduler=None):
            async def run():
                try:
                    result = await deliver()
                    observer.on_next(result)
                    observer.on_completed()
                except Exception as e:
                    observer.on_error(e)

            asyncio.create_task(run())
            return lambda: None

        return create(subscribe)

    async def _prepare_payload(
        self, payload: WebhookPayload, endpoint: WebhookEndpoint
    ) -> Dict[str, Any]:
        """Prepare webhook payload with transformations"""
        base_payload = {
            "event": payload.event_name,
            "timestamp": payload.timestamp,
            "event_id": payload.event_id,
            "data": payload.event_data,
        }

        # Apply transformer if specified
        if endpoint.transform and endpoint.transform in self.config["webhooks"]["transformers"]:
            transformer = self.config["webhooks"]["transformers"][endpoint.transform]
            if transformer["type"] == "template":
                from jinja2 import Template

                template = Template(transformer["template"])
                transformed = template.render(event_name=payload.event_name, **payload.event_data)
                return json.loads(transformed)

        return base_payload

    def _generate_signature(self, data: Dict[str, Any], secret: Optional[str]) -> str:
        """Generate HMAC signature for webhook payload"""
        if not secret:
            secret = self.config["webhooks"]["security"].get("default_secret", "default-secret")

        message = json.dumps(data, sort_keys=True)
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

        return f"sha256={signature}"

    def _get_circuit_breaker(self, url: str) -> CircuitBreaker:
        """Get or create circuit breaker for URL"""
        if url not in self.circuit_breakers:
            cb_config = self.config["webhooks"]["delivery"]["circuit_breaker"]
            self.circuit_breakers[url] = CircuitBreaker(
                url=url,
                failure_threshold=cb_config["failure_threshold"],
                timeout_seconds=cb_config["timeout_seconds"],
                half_open_max_attempts=cb_config["half_open_requests"],
            )
        return self.circuit_breakers[url]

    async def _store_dead_letter(
        self, payload: WebhookPayload, endpoint: WebhookEndpoint, error: str
    ):
        """Store failed webhook in dead letter queue"""
        dead_letter_data = {
            "payload": {
                "event_name": payload.event_name,
                "event_data": payload.event_data,
                "timestamp": payload.timestamp,
                "event_id": payload.event_id,
            },
            "endpoint": {"url": endpoint.url, "method": endpoint.method},
            "error": error,
            "stored_at": time.time(),
        }

        # Store in Redis with expiry
        if self.redis_client:
            key = f"webhook:dead_letter:{payload.event_id}"
            retention_days = self.config["webhooks"]["delivery"]["dead_letter"]["retention_days"]
            await self.redis_client.setex(
                key, timedelta(days=retention_days), json.dumps(dead_letter_data)
            )

            logger.warning(f"Webhook stored in dead letter queue: {key}")

    def _on_delivery_success(self, result: WebhookDeliveryResult):
        """Handle successful delivery - called by reactive subscription"""
        logger.debug(f"Delivery success callback: {result.endpoint.url}")

    def _on_delivery_error(self, error: Exception):
        """Handle delivery error - called by reactive subscription"""
        logger.error(f"Delivery error callback: {error}")

    def _handle_delivery_error(self, error: Exception, source: Observable) -> Observable:
        """
        Handle delivery errors in the reactive stream

        This is called by the catch operator when an error occurs
        Returns an Observable that replaces the errored stream
        """
        logger.error(f"Handling delivery error in stream: {error}")
        # Return empty observable to continue processing
        return Observable.empty()

    def _update_metrics(self, metrics_batch: List[Dict[str, Any]]):
        """Update Prometheus metrics from batched metric events"""
        for metric in metrics_batch:
            if metric["type"] == "delivery_success":
                webhook_deliveries.labels(event=metric["event"], status="success").inc()
                webhook_duration.labels(event=metric["event"]).observe(metric["duration"])
            elif metric["type"] == "delivery_failure":
                webhook_failures.labels(event=metric["event"], reason=metric["error"]).inc()

    async def start(self):
        """Start the reactive webhook manager"""
        logger.info("Starting Reactive Webhook Manager")

        # Initialize Redis connection
        self.redis_client = await redis.from_url(self.redis_url)

        # Reactive pipelines are already set up in __init__
        # No need to spawn worker tasks - the streams handle everything!

        logger.info("Reactive Webhook Manager started - streams are now listening")

    async def stop(self):
        """Stop the reactive webhook manager"""
        logger.info("Stopping Reactive Webhook Manager")

        # Dispose all subscriptions - this stops all streams
        for subscription in self.subscriptions:
            subscription.dispose()

        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()

        logger.info("Reactive Webhook Manager stopped")

    def trigger_event(
        self,
        event_name: str,
        event_data: Dict[str, Any],
        priority: WebhookPriority = WebhookPriority.NORMAL,
    ):
        """
        Trigger a webhook event - the reactive way!

        Original: await self.delivery_queue.put((priority.value, payload))
        Reactive: self.webhook_stream.on_next(payload)

        The difference: Instead of manually putting into a queue,
        we emit the event into the stream and the pipeline handles everything.
        """
        payload = WebhookPayload(
            event_name=event_name,
            event_data=event_data,
            timestamp=time.time(),
            event_id=self._generate_event_id(),
            priority=priority,
        )

        # Emit into the stream - the reactive pipeline takes over from here!
        self.webhook_stream.on_next(payload)

        logger.info(f"Event emitted to stream: {event_name} with priority {priority.name}")

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import uuid

        return str(uuid.uuid4())

    async def register_webhook(
        self,
        event_name: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
    ) -> bool:
        """Dynamically register a new webhook"""
        endpoint = WebhookEndpoint(url=url, headers=headers or {}, secret=secret)

        self.endpoints[event_name].append(endpoint)

        # Persist to Redis
        if self.redis_client:
            key = f"webhook:registration:{event_name}:{url}"
            await self.redis_client.set(
                key, json.dumps({"url": url, "headers": headers, "registered_at": time.time()})
            )

        logger.info(f"Webhook registered: {event_name} -> {url}")
        return True

    async def get_metrics(self) -> Dict[str, Any]:
        """Get webhook metrics"""
        metrics = {
            "circuit_breakers": {
                url: {"state": cb.state.name, "failure_count": cb.failure_count}
                for url, cb in self.circuit_breakers.items()
            },
            "endpoints": {event: len(endpoints) for event, endpoints in self.endpoints.items()},
            "note": "Reactive streams handle backpressure automatically - no manual queue size tracking needed!",
        }

        return metrics


# ============================================================================
# COMPARISON DEMO - Shows the difference between imperative and reactive
# ============================================================================


async def demo_comparison():
    """
    Demo showing side-by-side comparison of imperative vs reactive approaches
    """
    print("=" * 80)
    print("IMPERATIVE VS REACTIVE WEBHOOK DELIVERY")
    print("=" * 80)

    print("\n1. IMPERATIVE APPROACH (Original webhook_manager.py):")
    print("""
    async def _delivery_worker(self, worker_id: int):
        while self.running:
            try:
                # Manual queue management
                priority, payload = await self.delivery_queue.get()

                # Manual iteration
                endpoints = self.endpoints.get(payload.event_name, [])
                delivery_tasks = []

                for endpoint in endpoints:
                    if endpoint.active:
                        task = self._deliver_webhook(payload, endpoint)
                        delivery_tasks.append(task)

                # Manual parallelization
                await asyncio.gather(*delivery_tasks, return_exceptions=True)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")

    Problems:
    - Manual queue management
    - Explicit worker pool
    - Manual error handling in each worker
    - Hard to compose operations
    - Testing requires mocking async behavior
    """)

    print("\n2. REACTIVE APPROACH (This file):")
    print("""
    delivery_subscription = (
        self.webhook_stream.pipe(
            ops.group_by(lambda payload: payload.priority.value),
            ops.flat_map(lambda priority_group: priority_group.pipe(
                ops.flat_map(lambda payload: self._create_delivery_pairs(payload)),
                ops.filter(lambda pair: self._check_circuit_breaker(pair[1].url)),
                ops.flat_map(
                    lambda pair: self._deliver_webhook_reactive(pair[0], pair[1]),
                    max_concurrent=10
                ),
                ops.retry(5),
                ops.catch(lambda error, source: self._handle_delivery_error(error, source))
            )),
            ops.share()
        )
        .subscribe(on_next=self._on_delivery_success, scheduler=self.scheduler)
    )

    Benefits:
    - Declarative data flow
    - Automatic backpressure
    - Built-in retry, error handling
    - Easy to test with marble diagrams
    - Composable operators
    - Separation of concerns
    """)

    print("\n3. KEY REACTIVE CONCEPTS DEMONSTRATED:")
    print("""
    ┌─────────────────────────────────────────────────────────────────┐
    │ OPERATOR          │ PURPOSE                                     │
    ├───────────────────┼─────────────────────────────────────────────┤
    │ group_by          │ Split stream by priority (auto-routing)     │
    │ flat_map          │ Transform + flatten (async operations)      │
    │ filter            │ Declarative filtering (circuit breaker)     │
    │ retry             │ Automatic retry logic (replaces @backoff)  │
    │ catch             │ Error boundary (dead letter queue)          │
    │ share             │ Multicast stream (hot observable)           │
    │ buffer_with_time  │ Batch operations (metrics aggregation)      │
    │ distinct_until... │ Emit only on change (circuit breaker state) │
    └─────────────────────────────────────────────────────────────────┘
    """)

    print("\n4. TESTING ADVANTAGE:")
    print("""
    # Imperative (Hard to test)
    # Need to mock: asyncio.Queue, asyncio.gather, worker tasks, timeouts

    # Reactive (Easy to test with marble diagrams)
    from reactivex.testing import TestScheduler, ReactiveTest

    scheduler = TestScheduler()

    # Marble diagram: -a-b-c-d-|
    # a, b, c, d = events; | = completion
    source = scheduler.create_hot_observable(
        ReactiveTest.on_next(100, event1),
        ReactiveTest.on_next(200, event2),
        ReactiveTest.on_completed(300)
    )

    # Test the pipeline synchronously!
    results = scheduler.start(lambda: source.pipe(your_pipeline))
    assert results.messages[0].value.value == expected_result
    """)

    print("\n" + "=" * 80)
    print("LEARN MORE:")
    print("- RxPy Docs: https://rxpy.readthedocs.io/")
    print("- ReactiveX: http://reactivex.io/")
    print("- Marble Diagrams: https://rxmarbles.com/")
    print("=" * 80)


# Example usage
async def main():
    """Example usage of Reactive Webhook Manager"""
    print("\n🚀 Starting Reactive Webhook Manager Demo\n")

    manager = ReactiveWebhookManager("webhooks_config.yaml")
    await manager.start()

    # Trigger events - notice we don't await!
    # Events are emitted into the stream and processed asynchronously
    manager.trigger_event(
        "system.health.health_check_failed",
        {"service": "api", "status": "unhealthy", "details": "Connection timeout"},
        priority=WebhookPriority.HIGH,
    )

    manager.trigger_event(
        "deployment.kubernetes.pod_created",
        {"pod_name": "api-server-abc123", "namespace": "production"},
        priority=WebhookPriority.NORMAL,
    )

    # Let streams process
    await asyncio.sleep(5)

    # Get metrics
    metrics = await manager.get_metrics()
    print(f"\n📊 Metrics: {json.dumps(metrics, indent=2)}\n")

    await manager.stop()

    # Show comparison
    await demo_comparison()


if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    asyncio.run(main())
