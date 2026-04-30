# Cross-Cutting Concerns: Observability

## Overview
Observability is implemented through three pillars: metrics, logging, and tracing.

## Metrics Architecture

### Prometheus Stack
```
┌─────────────────────────────────────────────────────────────────┐
│                     Metrics Pipeline                             │
│                                                                  │
│  ┌──────────┐     ┌──────────────┐     ┌──────────────────┐    │
│  │ Services │────►│  Prometheus  │────►│     Grafana      │    │
│  │ /metrics │     │   Scraper    │     │   Dashboards     │    │
│  └──────────┘     └──────────────┘     └──────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│                   ┌──────────────┐                              │
│                   │ Alert Manager│                              │
│                   │   → PagerDuty│                              │
│                   └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

### Key Metrics

#### Application Metrics
```
# Request metrics
http_requests_total{method, endpoint, status}
http_request_duration_seconds{method, endpoint, quantile}

# Authentication metrics
auth_login_total{status}
auth_token_refresh_total{status}
auth_failures_total{reason}

# Business metrics
jobs_submitted_total{type, tenant}
jobs_completed_total{type, status}
active_subscriptions{plan}
```

#### Infrastructure Metrics
```
# Database metrics
pg_connections_active
pg_query_duration_seconds{query_type}
pg_deadlocks_total

# Redis metrics
redis_memory_used_bytes
redis_connected_clients
redis_commands_total{command}

# GPU metrics
gpu_utilization_percent{gpu_id}
gpu_memory_used_bytes{gpu_id}
gpu_temperature_celsius{gpu_id}
```

### Alerting Rules

```yaml
groups:
- name: platform
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.01
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"

  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "P95 latency above 500ms"

  - alert: GPUMemoryHigh
    expr: gpu_memory_used_bytes / gpu_memory_total_bytes > 0.9
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "GPU memory usage above 90%"
```

## Logging Architecture

### Structured Logging
```python
import structlog

logger = structlog.get_logger()

# Application log
logger.info(
    "job_completed",
    job_id=job_id,
    duration_ms=duration,
    backend="cupy",
    tenant_id=tenant_id
)
```

### Log Format
```json
{
  "timestamp": "2024-10-15T10:30:00.123Z",
  "level": "info",
  "event": "job_completed",
  "job_id": "job_abc123",
  "duration_ms": 1234,
  "backend": "cupy",
  "tenant_id": "tenant_xyz",
  "request_id": "req_789",
  "service": "catalytic-engine",
  "version": "1.2.3"
}
```

### Log Levels
| Level | Use Case | Retention |
|-------|----------|-----------|
| ERROR | Errors requiring attention | 90 days |
| WARN | Potential issues | 30 days |
| INFO | Business events | 14 days |
| DEBUG | Development debugging | 1 day |

### Log Categories
```
┌─────────────────────────────────────────────────────────────────┐
│                       Log Categories                             │
│                                                                  │
│  Category        │ Examples                  │ Alert On          │
│  ────────────────┼───────────────────────────┼─────────────────  │
│  access          │ HTTP requests             │ Error spikes      │
│  auth            │ Login, logout, refresh    │ Failures          │
│  audit           │ Data access, changes      │ Anomalies         │
│  security        │ Blocked requests, threats │ All events        │
│  business        │ Jobs, subscriptions       │ Failures          │
│  performance     │ Slow queries, timeouts    │ Thresholds        │
└─────────────────────────────────────────────────────────────────┘
```

## Tracing Architecture (Future)

### OpenTelemetry Integration
```python
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

tracer = trace.get_tracer(__name__)

async def process_job(job_id: str):
    with tracer.start_as_current_span("process_job") as span:
        span.set_attribute("job.id", job_id)

        with tracer.start_span("gpu_allocation"):
            gpu = await scheduler.allocate(job_id)
            span.set_attribute("gpu.id", gpu.id)

        with tracer.start_span("computation"):
            result = await backend.execute(job)

        span.set_status(Status(StatusCode.OK))
        return result
```

### Trace Context Propagation
```
Request → API Gateway → SaaS API → Catalytic Engine → GPU
   │          │            │              │            │
   └──────────┴────────────┴──────────────┴────────────┘
                    Trace ID: abc123
                    Spans: 5
```

## Health Checks

### Endpoint Specification
```yaml
# /health response
{
  "status": "healthy|degraded|unhealthy",
  "version": "1.2.3",
  "checks": {
    "database": {"status": "healthy", "latency_ms": 5},
    "redis": {"status": "healthy", "latency_ms": 2},
    "gpu": {"status": "healthy", "available": 2}
  },
  "timestamp": "2024-10-15T10:30:00Z"
}
```

### Health Check Strategy
| Check | Method | Timeout | Failure Threshold |
|-------|--------|---------|-------------------|
| Liveness | GET /health | 5s | 3 consecutive |
| Readiness | GET /health | 3s | 1 |
| Startup | GET /health | 60s | - |

## Dashboards

### Platform Overview Dashboard
- Request rate and latency
- Error rate by endpoint
- Active users and tenants
- Subscription status

### GPU Compute Dashboard
- Job queue length
- GPU utilization per node
- Backend distribution
- Compute throughput

### Security Dashboard
- Failed login attempts
- Rate limit triggers
- Suspicious activity
- Certificate expiration

---
**Last Updated**: 2024-10-15
