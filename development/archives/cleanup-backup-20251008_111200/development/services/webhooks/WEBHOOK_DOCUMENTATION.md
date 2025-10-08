# Webhook System Documentation

## Overview

A production-ready webhook system implementation with the following features:
- **Event-driven architecture** with publisher-subscriber pattern
- **Reliable delivery** with configurable retry logic and exponential backoff
- **Security** via HMAC-SHA256 signatures
- **Persistence** using SQLite database
- **Monitoring** with FastAPI dashboard and metrics
- **Async processing** for high throughput
- **Extensible** with adapters for GitHub, Slack, Discord, etc.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Event Source  │────>│  Webhook Manager │────>│ Remote Endpoint │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────┐
                        │   Database   │
                        │   (SQLite)   │
                        └──────────────┘
```

## Quick Start

### 1. Basic Usage

```python
from webhook_system import WebhookManager

# Initialize manager
manager = WebhookManager()
manager.start()

# Register a webhook
webhook_id = manager.register_webhook(
    url="https://example.com/webhook",
    events=["data.created", "data.updated"],
    secret="your-secret-key"
)

# Trigger an event
manager.trigger_event(
    event="data.created",
    data={"id": "123", "name": "Test Item"},
    metadata={"source": "api"}
)

manager.stop()
```

### 2. Run the Dashboard

```bash
# Start the webhook server with dashboard
python webhook_server.py

# Access at http://localhost:8000
# API docs at http://localhost:8000/docs
```

## Components

### 1. Core System (`webhook_system.py`)

#### WebhookManager
Main orchestrator for the webhook system.

```python
manager = WebhookManager(db_path="webhooks.db")
manager.start()

# Register webhook
webhook_id = manager.register_webhook(
    url="https://api.example.com/webhook",
    events=["order.created", "order.updated"],
    secret="secret-key",
    retry_count=3,
    retry_delay=5,
    timeout=30,
    headers={"X-API-Key": "key"}
)

# Trigger event
manager.trigger_event(
    event="order.created",
    data={"order_id": "ORD-123", "total": 99.99}
)
```

#### WebhookConfig
Configuration for individual webhooks.

**Parameters:**
- `url` (str): Endpoint URL
- `events` (List[str]): Event subscriptions (use "*" for all)
- `secret` (str, optional): HMAC signing secret
- `active` (bool): Enable/disable webhook
- `retry_count` (int): Max retry attempts (0-10)
- `retry_delay` (int): Delay between retries in seconds
- `timeout` (int): Request timeout in seconds
- `headers` (Dict): Custom headers
- `metadata` (Dict): Additional metadata

#### Event Types
Pre-defined event categories:

- **System**: `system.startup`, `system.shutdown`, `system.error`
- **Data**: `data.created`, `data.updated`, `data.deleted`
- **Process**: `process.started`, `process.completed`, `process.failed`
- **Monitoring**: `health.check`, `alert.triggered`, `metric.threshold`
- **Custom**: Any string for custom events

### 2. FastAPI Server (`webhook_server.py`)

Production-ready server with REST API and dashboard.

#### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| POST | `/api/webhooks` | Register webhook |
| GET | `/api/webhooks` | List all webhooks |
| GET | `/api/webhooks/{id}` | Get webhook details |
| PATCH | `/api/webhooks/{id}` | Update webhook |
| DELETE | `/api/webhooks/{id}` | Delete webhook |
| POST | `/api/events/trigger` | Trigger event |
| GET | `/api/events` | List event types |
| GET | `/api/deliveries` | Recent deliveries |
| GET | `/api/stats` | System statistics |
| POST | `/api/webhooks/test` | Test webhook |

#### Running the Server

```python
from webhook_server import run_server

# Run on custom port
run_server(host="0.0.0.0", port=8080)
```

### 3. Integration Examples (`webhook_examples.py`)

#### GitHub Integration

```python
from webhook_examples import GitHubWebhookAdapter

github = GitHubWebhookAdapter(manager)

# Handle GitHub push event
github.handle_push({
    "repository": {"full_name": "user/repo"},
    "pusher": {"name": "developer"},
    "commits": [...],
    "ref": "refs/heads/main"
})
```

#### Slack Notifications

```python
from webhook_examples import SlackWebhookNotifier

slack = SlackWebhookNotifier("https://hooks.slack.com/services/...")

# Send message
await slack.send_message("Deployment completed!", channel="#deployments")

# Send alert
await slack.send_alert(
    title="High CPU Usage",
    description="CPU usage exceeded 90%",
    color="warning"
)
```

#### Discord Notifications

```python
from webhook_examples import DiscordWebhookNotifier

discord = DiscordWebhookNotifier("https://discord.com/api/webhooks/...")

# Send embed
await discord.send_embed(
    title="New Order",
    description="Order #123 received",
    color=0x00FF00
)
```

#### Database Integration

```python
from webhook_examples import DatabaseWebhookIntegration

db_hooks = DatabaseWebhookIntegration(manager)

# Trigger on database changes
db_hooks.on_record_created("users", 123, {"name": "John", "email": "john@example.com"})
db_hooks.on_record_updated("users", 123, old_data, new_data)
db_hooks.on_record_deleted("users", 123)
```

## Security

### HMAC Signature Verification

Webhooks are signed using HMAC-SHA256:

```python
# Signature generation (automatic)
signature = hmac.new(
    secret.encode(),
    payload_json.encode(),
    hashlib.sha256
).hexdigest()

# Sent as header
X-Webhook-Signature: sha256=<signature>
```

### Verification Example

```python
def verify_webhook_signature(request_body, signature_header, secret):
    expected_sig = hmac.new(
        secret.encode(),
        request_body,
        hashlib.sha256
    ).hexdigest()
    
    provided_sig = signature_header.replace("sha256=", "")
    return hmac.compare_digest(expected_sig, provided_sig)
```

## Reliability

### Retry Logic

Failed deliveries are retried with exponential backoff:

- Attempt 1: Immediate
- Attempt 2: After `retry_delay` seconds
- Attempt 3: After `retry_delay * 2` seconds
- ...up to `retry_count` attempts

### Delivery Status

Track delivery status in the database:

```python
stats = manager.get_webhook_stats(webhook_id)
# Returns:
# {
#     'total_attempts': 10,
#     'successful': 8,
#     'failed': 2,
#     'avg_duration_ms': 234.5
# }
```

## Monitoring

### Dashboard Features

- **Real-time statistics**: Active webhooks, delivery rates, success rates
- **Recent deliveries**: View latest webhook deliveries with status
- **Webhook management**: Register, update, delete webhooks
- **Event testing**: Trigger test events directly from UI

### Metrics

System metrics available via `/api/stats`:

```json
{
  "webhooks": {
    "active": 5,
    "total": 8
  },
  "deliveries_24h": {
    "total": 1234,
    "successful": 1200,
    "failed": 34,
    "avg_duration_ms": 156.7
  }
}
```

## Performance

### Async Processing

- Non-blocking event triggering
- Parallel webhook deliveries
- Background task processing

### Batch Processing

```python
from webhook_examples import WebhookBatchProcessor

batch = WebhookBatchProcessor(manager, batch_size=100, flush_interval=5.0)

# Add events to batch
for i in range(1000):
    batch.add_event("data.created", {"id": i})

# Auto-flushes every 100 events or 5 seconds
await batch.flush()
```

## Database Schema

### webhooks table

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | Primary key |
| url | TEXT | Webhook URL |
| events | TEXT | JSON array of events |
| secret | TEXT | HMAC secret |
| active | BOOLEAN | Enable/disable |
| retry_count | INTEGER | Max retries |
| retry_delay | INTEGER | Retry delay (seconds) |
| timeout | INTEGER | Request timeout |
| headers | TEXT | JSON headers |
| metadata | TEXT | JSON metadata |
| created_at | TEXT | ISO timestamp |
| updated_at | TEXT | ISO timestamp |

### delivery_attempts table

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | Primary key |
| webhook_id | TEXT | Foreign key |
| payload_id | TEXT | Payload ID |
| attempt_number | INTEGER | Attempt count |
| status | TEXT | Delivery status |
| response_code | INTEGER | HTTP response code |
| response_body | TEXT | Response content |
| error_message | TEXT | Error if failed |
| timestamp | TEXT | ISO timestamp |
| duration_ms | REAL | Request duration |

## Testing

### Unit Tests

```bash
# Run webhook system tests
python test_webhooks.py

# Tests include:
# - Registration/unregistration
# - Event triggering
# - Statistics tracking
# - Persistence
# - Wildcard subscriptions
```

### Integration Testing

```python
# Test webhook endpoint
curl -X POST http://localhost:8000/api/webhooks/test \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/post",
    "event": "test.ping",
    "data": {"test": true}
  }'
```

## Best Practices

### 1. Event Naming

Use dot notation for hierarchical events:
- `resource.action` (e.g., `order.created`)
- `service.resource.action` (e.g., `payment.invoice.paid`)

### 2. Payload Structure

Keep payloads consistent:

```json
{
  "id": "unique-id",
  "event": "event.name",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    // Event-specific data
  },
  "metadata": {
    // Additional context
  }
}
```

### 3. Error Handling

- Use appropriate HTTP status codes
- Return meaningful error messages
- Implement circuit breakers for failing endpoints
- Log failures for debugging

### 4. Security

- Always use HTTPS endpoints
- Implement signature verification
- Rotate secrets regularly
- Validate webhook URLs
- Rate limit incoming requests

### 5. Performance

- Process webhooks asynchronously
- Implement reasonable timeouts
- Batch events when possible
- Use connection pooling
- Monitor queue depths

## Troubleshooting

### Common Issues

**Webhook not receiving events:**
- Check webhook is active
- Verify event subscription matches
- Check network connectivity
- Review delivery attempts in database

**Signature verification failing:**
- Ensure secret matches on both ends
- Verify payload serialization is consistent
- Check for encoding issues

**High failure rate:**
- Review timeout settings
- Check endpoint availability
- Monitor response times
- Implement circuit breakers

**Memory issues:**
- Limit queue sizes
- Implement batch processing
- Clean old delivery records
- Use connection pooling

## Migration Guide

### From Other Systems

#### From Zapier/IFTTT

1. Export webhook URLs and events
2. Register webhooks with matching events
3. Update payload format if needed
4. Test with sample events

#### From Custom Implementation

1. Map event types to new system
2. Update signature verification
3. Migrate historical data if needed
4. Run parallel for testing

## Conclusion

This webhook system provides a robust, scalable solution for event-driven architectures with:

- ✅ Reliable delivery with retries
- ✅ Security via HMAC signatures
- ✅ Persistence and recovery
- ✅ Monitoring and observability
- ✅ Easy integration with existing systems
- ✅ Production-ready with FastAPI
- ✅ Comprehensive testing

The system is designed to handle high throughput while maintaining reliability and security, making it suitable for production use in enterprise environments.