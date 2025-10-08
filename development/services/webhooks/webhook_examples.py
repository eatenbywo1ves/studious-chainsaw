"""
Webhook Integration Examples
Demonstrates how to integrate webhooks with various systems
"""

import asyncio
from typing import Dict, Any
from webhook_system import WebhookManager, WebhookPayload
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GitHubWebhookAdapter:
    """Adapter for GitHub webhook events"""

    def __init__(self, webhook_manager: WebhookManager):
        self.manager = webhook_manager

    def handle_push(self, payload: Dict[str, Any]):
        """Handle GitHub push event"""
        self.manager.trigger_event(
            event="github.push",
            data={
                "repository": payload.get("repository", {}).get("full_name"),
                "pusher": payload.get("pusher", {}).get("name"),
                "commits": len(payload.get("commits", [])),
                "branch": payload.get("ref", "").split("/")[-1]
            },
            metadata={"source": "github", "event_type": "push"}
        )

    def handle_pull_request(self, payload: Dict[str, Any]):
        """Handle GitHub pull request event"""
        pr = payload.get("pull_request", {})
        self.manager.trigger_event(
            event="github.pull_request",
            data={
                "action": payload.get("action"),
                "number": pr.get("number"),
                "title": pr.get("title"),
                "user": pr.get("user", {}).get("login"),
                "state": pr.get("state")
            },
            metadata={"source": "github", "event_type": "pull_request"}
        )

    def handle_issue(self, payload: Dict[str, Any]):
        """Handle GitHub issue event"""
        issue = payload.get("issue", {})
        self.manager.trigger_event(
            event="github.issue",
            data={
                "action": payload.get("action"),
                "number": issue.get("number"),
                "title": issue.get("title"),
                "user": issue.get("user", {}).get("login"),
                "state": issue.get("state")
            },
            metadata={"source": "github", "event_type": "issue"}
        )


class SlackWebhookNotifier:
    """Send notifications to Slack via webhooks"""

    def __init__(self, slack_webhook_url: str):
        self.webhook_url = slack_webhook_url

    async def send_message(self, text: str, channel: str = None, username: str = "Webhook Bot"):
        """Send message to Slack"""
        import httpx

        payload = {
            "text": text,
            "username": username
        }

        if channel:
            payload["channel"] = channel

        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=payload)
            return response.status_code == 200

    async def send_alert(self, title: str, description: str, color: str = "warning"):
        """Send formatted alert to Slack"""
        import httpx

        payload = {
            "attachments": [{
                "color": color,
                "title": title,
                "text": description,
                "footer": "Webhook System",
                "ts": int(asyncio.get_event_loop().time())
            }]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=payload)
            return response.status_code == 200


class DiscordWebhookNotifier:
    """Send notifications to Discord via webhooks"""

    def __init__(self, discord_webhook_url: str):
        self.webhook_url = discord_webhook_url

    async def send_message(self, content: str, username: str = None):
        """Send message to Discord"""
        import httpx

        payload = {"content": content}
        if username:
            payload["username"] = username

        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=payload)
            return response.status_code == 204

    async def send_embed(self, title: str, description: str, color: int = 0xFF5733):
        """Send embedded message to Discord"""
        import httpx

        payload = {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "footer": {"text": "Webhook System"},
                "timestamp": datetime.now().isoformat()
            }]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=payload)
            return response.status_code == 204


class DatabaseWebhookIntegration:
    """Integration with database events"""

    def __init__(self, webhook_manager: WebhookManager):
        self.manager = webhook_manager

    def on_record_created(self, table: str, record_id: Any, data: Dict[str, Any]):
        """Trigger webhook on record creation"""
        self.manager.trigger_event(
            event="database.record.created",
            data={
                "table": table,
                "id": str(record_id),
                "data": data
            },
            metadata={"operation": "insert"}
        )

    def on_record_updated(self, table: str, record_id: Any,
                         old_data: Dict[str, Any], new_data: Dict[str, Any]):
        """Trigger webhook on record update"""
        changes = {}
        for key in new_data:
            if key in old_data and old_data[key] != new_data[key]:
                changes[key] = {
                    "old": old_data[key],
                    "new": new_data[key]
                }

        self.manager.trigger_event(
            event="database.record.updated",
            data={
                "table": table,
                "id": str(record_id),
                "changes": changes
            },
            metadata={"operation": "update"}
        )

    def on_record_deleted(self, table: str, record_id: Any):
        """Trigger webhook on record deletion"""
        self.manager.trigger_event(
            event="database.record.deleted",
            data={
                "table": table,
                "id": str(record_id)
            },
            metadata={"operation": "delete"}
        )


class MonitoringWebhookIntegration:
    """Integration with monitoring systems"""

    def __init__(self, webhook_manager: WebhookManager):
        self.manager = webhook_manager
        self.thresholds = {}

    def set_threshold(self, metric: str, threshold: float):
        """Set metric threshold"""
        self.thresholds[metric] = threshold

    def check_metric(self, metric: str, value: float):
        """Check metric and trigger webhook if threshold exceeded"""
        if metric in self.thresholds:
            threshold = self.thresholds[metric]
            if value > threshold:
                self.manager.trigger_event(
                    event="monitoring.threshold.exceeded",
                    data={
                        "metric": metric,
                        "value": value,
                        "threshold": threshold,
                        "exceeded_by": value - threshold
                    },
                    metadata={"severity": "warning" if value < threshold * 1.5 else "critical"}
                )
                return True
        return False

    def send_health_check(self, service: str, status: str, details: Dict[str, Any] = None):
        """Send health check webhook"""
        self.manager.trigger_event(
            event="monitoring.health.check",
            data={
                "service": service,
                "status": status,
                "details": details or {},
                "timestamp": datetime.now().isoformat()
            },
            metadata={"type": "health_check"}
        )


class PaymentWebhookIntegration:
    """Integration with payment systems (Stripe-like)"""

    def __init__(self, webhook_manager: WebhookManager):
        self.manager = webhook_manager

    def payment_succeeded(self, payment_id: str, amount: float, currency: str,
                         customer_id: str):
        """Handle successful payment"""
        self.manager.trigger_event(
            event="payment.succeeded",
            data={
                "payment_id": payment_id,
                "amount": amount,
                "currency": currency,
                "customer_id": customer_id,
                "status": "succeeded"
            },
            metadata={"type": "payment", "processor": "stripe"}
        )

    def payment_failed(self, payment_id: str, amount: float, currency: str,
                      customer_id: str, error: str):
        """Handle failed payment"""
        self.manager.trigger_event(
            event="payment.failed",
            data={
                "payment_id": payment_id,
                "amount": amount,
                "currency": currency,
                "customer_id": customer_id,
                "status": "failed",
                "error": error
            },
            metadata={"type": "payment", "processor": "stripe"}
        )

    def subscription_created(self, subscription_id: str, customer_id: str,
                           plan: str, amount: float):
        """Handle subscription creation"""
        self.manager.trigger_event(
            event="subscription.created",
            data={
                "subscription_id": subscription_id,
                "customer_id": customer_id,
                "plan": plan,
                "amount": amount,
                "status": "active"
            },
            metadata={"type": "subscription"}
        )


class WebhookBatchProcessor:
    """Process webhooks in batches for efficiency"""

    def __init__(self, webhook_manager: WebhookManager, batch_size: int = 100,
                 flush_interval: float = 5.0):
        self.manager = webhook_manager
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = []
        self.last_flush = asyncio.get_event_loop().time()

    def add_event(self, event: str, data: Dict[str, Any], metadata: Dict[str, Any] = None):
        """Add event to batch"""
        self.buffer.append({
            "event": event,
            "data": data,
            "metadata": metadata or {}
        })

        # Check if we should flush
        if len(self.buffer) >= self.batch_size:
            asyncio.create_task(self.flush())

    async def flush(self):
        """Flush batched events"""
        if not self.buffer:
            return

        # Create batch event
        batch_data = {
            "events": self.buffer,
            "count": len(self.buffer),
            "timestamp": datetime.now().isoformat()
        }

        self.manager.trigger_event(
            event="batch.events",
            data=batch_data,
            metadata={"batch_size": len(self.buffer)}
        )

        logger.info(f"Flushed batch of {len(self.buffer)} events")
        self.buffer.clear()
        self.last_flush = asyncio.get_event_loop().time()

    async def auto_flush_loop(self):
        """Auto-flush loop"""
        while True:
            await asyncio.sleep(self.flush_interval)
            if self.buffer and (asyncio.get_event_loop().time() - self.last_flush) >= self.flush_interval:
                await self.flush()


# Example: Complete integration scenario
async def complete_integration_example():
    """Demonstrate complete webhook integration"""

    # Initialize webhook manager
    manager = WebhookManager()
    manager.start()

    try:
        # Register webhooks for different services

        # Slack webhook for critical alerts
        slack_webhook_id = manager.register_webhook(
            url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
            events=["monitoring.threshold.exceeded", "payment.failed"],
            secret="slack-secret"
        )

        # Analytics service webhook for all events
        analytics_webhook_id = manager.register_webhook(
            url="https://analytics.example.com/webhook",
            events=["*"],  # Receive all events
            secret="analytics-secret",
            headers={"X-API-Key": "your-api-key"}
        )

        # Database backup service for data events
        backup_webhook_id = manager.register_webhook(
            url="https://backup.example.com/webhook",
            events=["database.record.created", "database.record.updated", "database.record.deleted"],
            retry_count=5,
            retry_delay=10
        )

        # Initialize integrations
        monitoring = MonitoringWebhookIntegration(manager)
        database = DatabaseWebhookIntegration(manager)
        payment = PaymentWebhookIntegration(manager)

        # Set monitoring thresholds
        monitoring.set_threshold("cpu_usage", 80.0)
        monitoring.set_threshold("memory_usage", 90.0)
        monitoring.set_threshold("disk_usage", 85.0)

        # Simulate events

        # 1. Health check
        monitoring.send_health_check("api-server", "healthy", {
            "uptime": 3600,
            "requests_per_second": 150
        })

        # 2. Database operations
        database.on_record_created("users", 123, {
            "name": "John Doe",
            "email": "john@example.com"
        })

        # 3. Payment event
        payment.payment_succeeded(
            payment_id="pay_123",
            amount=99.99,
            currency="USD",
            customer_id="cust_456"
        )

        # 4. Metric threshold exceeded
        monitoring.check_metric("cpu_usage", 95.0)

        # Wait for deliveries
        await asyncio.sleep(10)

        # Get statistics
        print("\n=== Webhook Statistics ===")
        for webhook_id in [slack_webhook_id, analytics_webhook_id, backup_webhook_id]:
            stats = manager.get_webhook_stats(webhook_id)
            print(f"Webhook {webhook_id[:8]}...")
            print(f"  Total attempts: {stats['total_attempts']}")
            print(f"  Successful: {stats['successful']}")
            print(f"  Failed: {stats['failed']}")
            print(f"  Avg duration: {stats['avg_duration_ms']:.2f}ms\n")

    finally:
        manager.stop()


# Example: Webhook chaining
class WebhookChain:
    """Chain webhooks for complex workflows"""

    def __init__(self, webhook_manager: WebhookManager):
        self.manager = webhook_manager
        self.chains = {}

    def add_chain(self, trigger_event: str, chain_events: List[str]):
        """Add event chain"""
        self.chains[trigger_event] = chain_events

        # Register handler for trigger event
        def chain_handler(payload: WebhookPayload):
            for event in chain_events:
                self.manager.trigger_event(
                    event=event,
                    data=payload.data,
                    metadata={**payload.metadata, "chained_from": trigger_event}
                )

        self.manager.add_event_handler(trigger_event, chain_handler)

    def example_workflow(self):
        """Example: Order processing workflow"""
        self.add_chain(
            trigger_event="order.created",
            chain_events=[
                "payment.process",
                "inventory.reserve",
                "notification.send_confirmation"
            ]
        )

        self.add_chain(
            trigger_event="payment.succeeded",
            chain_events=[
                "order.confirm",
                "shipping.prepare",
                "notification.send_receipt"
            ]
        )


if __name__ == "__main__":
    # Run example
    from datetime import datetime
    asyncio.run(complete_integration_example())
