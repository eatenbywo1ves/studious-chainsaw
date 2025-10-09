"""
Comprehensive Webhook System Implementation
Supports registration, authentication, retry logic, and event filtering
"""

import asyncio
import aiohttp
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
from urllib.parse import urlparse
import sqlite3
import threading
from queue import Queue, Empty

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebhookEvent(Enum):
    """Supported webhook event types"""

    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"

    # Data events
    DATA_CREATED = "data.created"
    DATA_UPDATED = "data.updated"
    DATA_DELETED = "data.deleted"

    # Process events
    PROCESS_STARTED = "process.started"
    PROCESS_COMPLETED = "process.completed"
    PROCESS_FAILED = "process.failed"

    # Monitoring events
    HEALTH_CHECK = "health.check"
    ALERT_TRIGGERED = "alert.triggered"
    METRIC_THRESHOLD = "metric.threshold"

    # Custom events
    CUSTOM = "custom.event"


class DeliveryStatus(Enum):
    """Webhook delivery status"""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    url: str = ""
    events: List[str] = field(default_factory=list)
    secret: Optional[str] = None
    active: bool = True
    retry_count: int = 3
    retry_delay: int = 5  # seconds
    timeout: int = 30  # seconds
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class WebhookPayload:
    """Webhook payload structure"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeliveryAttempt:
    """Record of a webhook delivery attempt"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    webhook_id: str = ""
    payload_id: str = ""
    attempt_number: int = 1
    status: DeliveryStatus = DeliveryStatus.PENDING
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_ms: Optional[float] = None


class WebhookRegistry:
    """Registry for managing webhook configurations"""

    def __init__(self, db_path: str = "webhooks.db"):
        self.db_path = db_path
        self.webhooks: Dict[str, WebhookConfig] = {}
        self._init_database()
        self._load_webhooks()

    def _init_database(self):
        """Initialize SQLite database for webhook persistence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                events TEXT,
                secret TEXT,
                active BOOLEAN DEFAULT 1,
                retry_count INTEGER DEFAULT 3,
                retry_delay INTEGER DEFAULT 5,
                timeout INTEGER DEFAULT 30,
                headers TEXT,
                metadata TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS delivery_attempts (
                id TEXT PRIMARY KEY,
                webhook_id TEXT,
                payload_id TEXT,
                attempt_number INTEGER,
                status TEXT,
                response_code INTEGER,
                response_body TEXT,
                error_message TEXT,
                timestamp TEXT,
                duration_ms REAL,
                FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
            )
        """)

        conn.commit()
        conn.close()

    def _load_webhooks(self):
        """Load webhooks from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM webhooks WHERE active = 1")
        rows = cursor.fetchall()

        for row in rows:
            webhook = WebhookConfig(
                id=row[0],
                url=row[1],
                events=json.loads(row[2]) if row[2] else [],
                secret=row[3],
                active=bool(row[4]),
                retry_count=row[5],
                retry_delay=row[6],
                timeout=row[7],
                headers=json.loads(row[8]) if row[8] else {},
                metadata=json.loads(row[9]) if row[9] else {},
                created_at=row[10],
                updated_at=row[11],
            )
            self.webhooks[webhook.id] = webhook

        conn.close()
        logger.info(f"Loaded {len(self.webhooks)} webhooks from database")

    def register(self, webhook: WebhookConfig) -> str:
        """Register a new webhook"""
        # Validate URL
        parsed = urlparse(webhook.url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid webhook URL: {webhook.url}")

        # Store in memory
        self.webhooks[webhook.id] = webhook

        # Persist to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO webhooks
            (id, url, events, secret, active, retry_count, retry_delay,
             timeout, headers, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                webhook.id,
                webhook.url,
                json.dumps(webhook.events),
                webhook.secret,
                webhook.active,
                webhook.retry_count,
                webhook.retry_delay,
                webhook.timeout,
                json.dumps(webhook.headers),
                json.dumps(webhook.metadata),
                webhook.created_at,
                webhook.updated_at,
            ),
        )

        conn.commit()
        conn.close()

        logger.info(f"Registered webhook {webhook.id} for {webhook.url}")
        return webhook.id

    def unregister(self, webhook_id: str):
        """Unregister a webhook"""
        if webhook_id in self.webhooks:
            del self.webhooks[webhook_id]

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE webhooks SET active = 0 WHERE id = ?", (webhook_id,))
            conn.commit()
            conn.close()

            logger.info(f"Unregistered webhook {webhook_id}")

    def get_webhooks_for_event(self, event: str) -> List[WebhookConfig]:
        """Get all webhooks subscribed to an event"""
        matching = []
        for webhook in self.webhooks.values():
            if webhook.active and (event in webhook.events or "*" in webhook.events):
                matching.append(webhook)
        return matching

    def update_webhook(self, webhook_id: str, updates: Dict[str, Any]):
        """Update webhook configuration"""
        if webhook_id in self.webhooks:
            webhook = self.webhooks[webhook_id]
            for key, value in updates.items():
                if hasattr(webhook, key):
                    setattr(webhook, key, value)
            webhook.updated_at = datetime.now().isoformat()

            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Build update query dynamically
            update_fields = []
            update_values = []
            for key, value in updates.items():
                if key in ["events", "headers", "metadata"]:
                    update_values.append(json.dumps(value))
                else:
                    update_values.append(value)
                update_fields.append(f"{key} = ?")

            update_values.append(webhook.updated_at)
            update_fields.append("updated_at = ?")
            update_values.append(webhook_id)

            query = f"UPDATE webhooks SET {', '.join(update_fields)} WHERE id = ?"
            cursor.execute(query, update_values)

            conn.commit()
            conn.close()

            logger.info(f"Updated webhook {webhook_id}")


class WebhookDelivery:
    """Handles webhook delivery with retry logic"""

    def __init__(self, registry: WebhookRegistry):
        self.registry = registry
        self.delivery_queue = Queue()
        self.worker_thread = None
        self.running = False

    def start(self):
        """Start the delivery worker"""
        self.running = True
        self.worker_thread = threading.Thread(target=self._delivery_worker)
        self.worker_thread.start()
        logger.info("Webhook delivery worker started")

    def stop(self):
        """Stop the delivery worker"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join()
        logger.info("Webhook delivery worker stopped")

    def _delivery_worker(self):
        """Worker thread for processing webhook deliveries"""
        while self.running:
            try:
                # Get delivery task from queue
                task = self.delivery_queue.get(timeout=1)
                webhook, payload = task

                # Attempt delivery
                asyncio.run(self._deliver_webhook(webhook, payload))

            except Empty:
                continue
            except Exception as e:
                logger.error(f"Delivery worker error: {e}")

    async def _deliver_webhook(self, webhook: WebhookConfig, payload: WebhookPayload):
        """Deliver webhook with retry logic"""
        attempt_number = 0

        while attempt_number < webhook.retry_count:
            attempt_number += 1
            attempt = DeliveryAttempt(
                webhook_id=webhook.id, payload_id=payload.id, attempt_number=attempt_number
            )

            start_time = time.time()

            try:
                # Prepare request
                headers = webhook.headers.copy()
                headers["Content-Type"] = "application/json"
                headers["X-Webhook-ID"] = webhook.id
                headers["X-Webhook-Event"] = payload.event
                headers["X-Webhook-Timestamp"] = payload.timestamp

                # Add signature if secret is configured
                if webhook.secret:
                    signature = self._generate_signature(webhook.secret, payload)
                    headers["X-Webhook-Signature"] = signature

                # Send request
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        webhook.url,
                        json=asdict(payload),
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=webhook.timeout),
                    ) as response:
                        attempt.response_code = response.status
                        attempt.response_body = await response.text()

                        if 200 <= response.status < 300:
                            attempt.status = DeliveryStatus.DELIVERED
                            attempt.duration_ms = (time.time() - start_time) * 1000
                            self._record_attempt(attempt)
                            logger.info(f"Webhook delivered: {webhook.id} -> {webhook.url}")
                            return
                        else:
                            raise Exception(f"HTTP {response.status}: {attempt.response_body}")

            except asyncio.TimeoutError:
                attempt.status = DeliveryStatus.FAILED
                attempt.error_message = "Request timeout"
                logger.warning(f"Webhook timeout: {webhook.id} -> {webhook.url}")

            except Exception as e:
                attempt.status = DeliveryStatus.FAILED
                attempt.error_message = str(e)
                logger.error(f"Webhook delivery failed: {webhook.id} -> {e}")

            attempt.duration_ms = (time.time() - start_time) * 1000
            self._record_attempt(attempt)

            # Wait before retry
            if attempt_number < webhook.retry_count:
                await asyncio.sleep(webhook.retry_delay * attempt_number)
                attempt.status = DeliveryStatus.RETRYING

    def _generate_signature(self, secret: str, payload: WebhookPayload) -> str:
        """Generate HMAC signature for webhook payload"""
        payload_json = json.dumps(asdict(payload), sort_keys=True)
        signature = hmac.new(secret.encode(), payload_json.encode(), hashlib.sha256).hexdigest()
        return f"sha256={signature}"

    def _record_attempt(self, attempt: DeliveryAttempt):
        """Record delivery attempt in database"""
        conn = sqlite3.connect(self.registry.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO delivery_attempts
            (id, webhook_id, payload_id, attempt_number, status,
             response_code, response_body, error_message, timestamp, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                attempt.id,
                attempt.webhook_id,
                attempt.payload_id,
                attempt.attempt_number,
                attempt.status.value,
                attempt.response_code,
                attempt.response_body,
                attempt.error_message,
                attempt.timestamp,
                attempt.duration_ms,
            ),
        )

        conn.commit()
        conn.close()

    def queue_delivery(self, webhook: WebhookConfig, payload: WebhookPayload):
        """Queue a webhook for delivery"""
        self.delivery_queue.put((webhook, payload))


class WebhookManager:
    """Main webhook management system"""

    def __init__(self, db_path: str = "webhooks.db"):
        self.registry = WebhookRegistry(db_path)
        self.delivery = WebhookDelivery(self.registry)
        self.event_handlers: Dict[str, List[Callable]] = {}

    def start(self):
        """Start the webhook system"""
        self.delivery.start()
        logger.info("Webhook system started")

    def stop(self):
        """Stop the webhook system"""
        self.delivery.stop()
        logger.info("Webhook system stopped")

    def register_webhook(
        self,
        url: str,
        events: List[str],
        secret: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> str:
        """Register a new webhook endpoint"""
        webhook = WebhookConfig(
            url=url, events=events, secret=secret, headers=headers or {}, **kwargs
        )
        return self.registry.register(webhook)

    def trigger_event(
        self, event: str, data: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None
    ):
        """Trigger a webhook event"""
        # Create payload
        payload = WebhookPayload(event=event, data=data, metadata=metadata or {})

        # Get matching webhooks
        webhooks = self.registry.get_webhooks_for_event(event)

        # Queue deliveries
        for webhook in webhooks:
            self.delivery.queue_delivery(webhook, payload)

        # Call local handlers
        if event in self.event_handlers:
            for handler in self.event_handlers[event]:
                try:
                    handler(payload)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

        logger.info(f"Triggered event {event} to {len(webhooks)} webhooks")

    def add_event_handler(self, event: str, handler: Callable):
        """Add a local event handler"""
        if event not in self.event_handlers:
            self.event_handlers[event] = []
        self.event_handlers[event].append(handler)

    def get_webhook_stats(self, webhook_id: str) -> Dict[str, Any]:
        """Get delivery statistics for a webhook"""
        conn = sqlite3.connect(self.registry.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                COUNT(*) as total_attempts,
                SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                AVG(duration_ms) as avg_duration_ms
            FROM delivery_attempts
            WHERE webhook_id = ?
        """,
            (webhook_id,),
        )

        row = cursor.fetchone()
        conn.close()

        return {
            "webhook_id": webhook_id,
            "total_attempts": row[0],
            "successful": row[1],
            "failed": row[2],
            "avg_duration_ms": row[3],
        }


class WebhookServer:
    """HTTP server for receiving webhooks"""

    def __init__(self, port: int = 8080):
        self.port = port
        self.app = None
        self.runner = None
        self.received_webhooks = []

    async def start(self):
        """Start the webhook receiver server"""
        from aiohttp import web

        self.app = web.Application()
        self.app.router.add_post("/webhook", self.handle_webhook)
        self.app.router.add_get("/health", self.health_check)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "localhost", self.port)
        await site.start()

        logger.info(f"Webhook server started on port {self.port}")

    async def stop(self):
        """Stop the webhook receiver server"""
        if self.runner:
            await self.runner.cleanup()
        logger.info("Webhook server stopped")

    async def handle_webhook(self, request):
        """Handle incoming webhook"""
        from aiohttp import web

        try:
            # Parse request
            data = await request.json()
            headers = dict(request.headers)

            # Verify signature if present
            if "X-Webhook-Signature" in headers:
                # Implement signature verification
                pass

            # Store received webhook
            self.received_webhooks.append(
                {"timestamp": datetime.now().isoformat(), "headers": headers, "data": data}
            )

            logger.info(f"Received webhook: {data.get('event', 'unknown')}")

            return web.json_response({"status": "received"}, status=200)

        except Exception as e:
            logger.error(f"Error handling webhook: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def health_check(self, request):
        """Health check endpoint"""
        from aiohttp import web

        return web.json_response({"status": "healthy"}, status=200)


# Example usage and testing
def example_usage():
    """Example of how to use the webhook system"""

    # Initialize webhook manager
    manager = WebhookManager()
    manager.start()

    try:
        # Register a webhook
        webhook_id = manager.register_webhook(
            url="https://example.com/webhook",
            events=["data.created", "data.updated"],
            secret="my-secret-key",
            headers={"X-Custom-Header": "value"},
        )
        print(f"Registered webhook: {webhook_id}")

        # Add local event handler
        def log_event(payload: WebhookPayload):
            print(f"Local handler: {payload.event} - {payload.data}")

        manager.add_event_handler("data.created", log_event)

        # Trigger an event
        manager.trigger_event(
            event="data.created",
            data={"id": "123", "name": "Test Item"},
            metadata={"source": "example"},
        )

        # Wait for deliveries
        time.sleep(5)

        # Get statistics
        stats = manager.get_webhook_stats(webhook_id)
        print(f"Webhook stats: {stats}")

    finally:
        manager.stop()


if __name__ == "__main__":
    # Run example
    example_usage()

    # Run webhook server for testing
    async def run_server():
        server = WebhookServer(port=8081)
        await server.start()

        # Keep running
        try:
            await asyncio.sleep(3600)
        finally:
            await server.stop()

    # Uncomment to run server
    # asyncio.run(run_server())
