# PRD: Monitoring Integration Tests

**Feature**: `test_monitoring_integration.py`
**Product Manager**: BMAD Product Manager Agent
**Date**: 2025-10-05
**Priority**: HIGH
**Effort Estimate**: Medium (4-6 hours)

---

## User Story

As a **SaaS platform operator**, I want **integration tests validating the monitoring stack works correctly** so that I can **detect and respond to production issues before they impact users**.

---

## Business Context

The SaaS platform implements a **comprehensive monitoring stack**:
- Prometheus metrics collection
- Grafana dashboards
- Alert rules for critical conditions
- Webhook notifications for incidents

**Current State**:
- Prometheus/Grafana deployed
- Metrics instrumented in code
- **Gap**: No integration tests validating metrics are collected and alerts trigger

**Operational Requirement**: Can't deploy to production without validated monitoring.

---

## Acceptance Criteria

### AC1: Prometheus Metrics Collection
- [ ] Prometheus successfully scrapes `/metrics` endpoint
- [ ] All instrumented metrics appear in Prometheus
- [ ] Metrics have correct labels (tenant_id, endpoint, method)
- [ ] Counter metrics increment correctly
- [ ] Histogram metrics record distributions
- [ ] Gauge metrics reflect current state

### AC2: Application Metrics Accuracy
- [ ] HTTP request count metric increments per request
- [ ] HTTP request duration recorded correctly
- [ ] Error rate metric tracks 4xx/5xx responses
- [ ] Active user gauge reflects concurrent users
- [ ] GPU utilization metric (when GPU in use)
- [ ] Database connection pool metrics

### AC3: Grafana Dashboard Queries
- [ ] Dashboard queries return data from Prometheus
- [ ] Queries complete in < 5 seconds
- [ ] Time series data formatted correctly
- [ ] Aggregations (sum, avg, rate) work correctly
- [ ] Dashboard variables populated

### AC4: Alert Rule Evaluation
- [ ] Alert rules are loaded in Prometheus
- [ ] Alerts trigger when conditions met
- [ ] Alerts clear when conditions resolve
- [ ] Alert labels include context (severity, tenant, etc.)
- [ ] Alert descriptions are helpful

### AC5: Webhook Alert Delivery
- [ ] Alerts trigger webhook notifications
- [ ] Webhook payload includes alert details
- [ ] Webhook retries on failure
- [ ] Multiple webhooks can be configured
- [ ] Webhook delivery logged

### AC6: End-to-End Monitoring Flow
- [ ] Trigger condition → Metric recorded → Alert fires → Webhook delivered
- [ ] Complete flow works in < 60 seconds
- [ ] All components communicate correctly

---

## Technical Requirements

### Prometheus Metrics Exposed

**HTTP Metrics** (from `saas/api/metrics_instrumentation.py`):
- `http_requests_total{method,endpoint,status}` - Counter
- `http_request_duration_seconds{method,endpoint}` - Histogram
- `http_requests_in_progress{method,endpoint}` - Gauge

**Application Metrics**:
- `active_users{tenant_id}` - Gauge
- `lattice_transformations_total{tenant_id,transformation_type}` - Counter
- `lattice_transformation_duration_seconds` - Histogram
- `gpu_utilization_percent` - Gauge
- `db_connections_active` - Gauge
- `cache_hit_rate` - Gauge

**Business Metrics**:
- `api_calls_per_tenant{tenant_id}` - Counter
- `revenue_events{event_type}` - Counter
- `user_registrations_total` - Counter

### Alert Rules Tested

```yaml
# prometheus-rules.yml
groups:
  - name: saas_alerts
    interval: 10s
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[1m]) > 0.05
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[1m])) > 2
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected (p95 > 2s)"

      - alert: GPUDown
        expr: gpu_utilization_percent == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "GPU appears unavailable"
```

### Grafana Dashboards Tested

**Dashboard**: "SaaS Overview"
- Panel 1: Request rate (rate of http_requests_total)
- Panel 2: Error rate (rate of 5xx responses)
- Panel 3: Latency (p50, p95, p99)
- Panel 4: Active users
- Panel 5: GPU utilization

### Test Scenarios

#### Scenario 1: Basic Metrics Collection
1. Start Prometheus
2. Make API requests
3. Query Prometheus for metrics
4. Verify metrics present and accurate

#### Scenario 2: Alert Triggering
1. Trigger high error rate condition (return 500s)
2. Wait for alert evaluation interval
3. Verify alert fires in Prometheus
4. Verify webhook notification sent

#### Scenario 3: Dashboard Query
1. Send traffic to generate metrics
2. Query Grafana API for dashboard data
3. Verify panels return expected data
4. Verify visualizations render

#### Scenario 4: Multi-Tenant Metrics
1. Create requests from multiple tenants
2. Verify metrics tagged with tenant_id
3. Query metrics filtered by tenant
4. Verify tenant isolation in metrics

---

## Edge Cases

### EC1: Prometheus Down
**Scenario**: Prometheus unavailable during scrape
**Expected**: Metrics buffered, no application impact

### EC2: Metrics Endpoint Slow
**Scenario**: `/metrics` endpoint takes > 10s to respond
**Expected**: Prometheus scrape timeout, retries

### EC3: Alert Flapping
**Scenario**: Condition rapidly crosses alert threshold
**Expected**: Alert hysteresis prevents flapping

### EC4: Webhook Endpoint Down
**Scenario**: Webhook destination unreachable
**Expected**: Retries with exponential backoff, logs failure

### EC5: Very High Cardinality
**Scenario**: Too many unique label values
**Expected**: Prometheus memory growth, potential OOM

---

## Success Metrics

### Metrics Coverage
- **Target**: 100% of critical paths instrumented
- **Measure**: Code coverage of metrics instrumentation

### Alert Accuracy
- **Target**: 0 false positives in test runs
- **Measure**: Alert firing only when condition met

### Performance
- **Target**: Metrics scrape < 100ms
- **Measure**: `/metrics` endpoint response time

### Reliability
- **Target**: 99.9% metrics delivery success
- **Measure**: Scrape success rate in Prometheus

---

## Test Structure

```python
# tests/integration/test_monitoring_integration.py

import pytest
import asyncio
import requests
from prometheus_client.parser import text_string_to_metric_families


class TestPrometheusMetrics:
    """Test Prometheus metrics collection"""

    async def test_metrics_endpoint_accessible(api_client):
        """Metrics endpoint returns data"""
        response = await api_client.get("/metrics")
        assert response.status_code == 200
        assert "http_requests_total" in response.text

    async def test_http_request_counter(api_client):
        """HTTP request counter increments"""
        # Get initial count
        before = await get_metric_value("http_requests_total")

        # Make request
        await api_client.get("/api/v1/lattices")

        # Verify increment
        after = await get_metric_value("http_requests_total")
        assert after > before

    async def test_request_duration_histogram(api_client):
        """Request duration histogram records timings"""
        await api_client.get("/api/v1/lattices")

        # Verify histogram bucket counts
        metrics = await get_metric_families()
        duration_metric = metrics["http_request_duration_seconds"]
        assert len(duration_metric.samples) > 0

    async def test_error_rate_metric(api_client):
        """Error rate metric tracks 5xx responses"""
        # Trigger error
        await api_client.get("/api/v1/nonexistent")

        # Verify error counter
        errors = await get_metric_value("http_requests_total", {"status": "404"})
        assert errors > 0


class TestApplicationMetrics:
    """Test application-specific metrics"""

    async def test_active_users_gauge(authenticated_client):
        """Active users gauge reflects current users"""
        metric_value = await get_metric_value("active_users")
        assert metric_value >= 1  # At least the test user

    async def test_transformation_counter(authenticated_client, sample_lattice_data):
        """Transformation counter increments"""
        # Create lattice
        lattice_response = await authenticated_client.post(
            "/api/v1/lattices",
            json=sample_lattice_data
        )
        lattice_id = lattice_response.json()["id"]

        before = await get_metric_value("lattice_transformations_total")

        # Perform transformation
        await authenticated_client.post(
            f"/api/v1/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor"}
        )

        after = await get_metric_value("lattice_transformations_total")
        assert after > before

    @pytest.mark.gpu_required
    async def test_gpu_utilization_metric(authenticated_client):
        """GPU utilization metric updates during GPU work"""
        # Trigger GPU transformation
        # (implementation details...)

        gpu_util = await get_metric_value("gpu_utilization_percent")
        assert 0 <= gpu_util <= 100


class TestGrafanaDashboards:
    """Test Grafana dashboard queries"""

    async def test_dashboard_query_executes(grafana_client):
        """Dashboard query returns data from Prometheus"""
        query = 'rate(http_requests_total[1m])'
        result = await grafana_client.query(query)
        assert result["status"] == "success"
        assert len(result["data"]["result"]) > 0

    async def test_dashboard_panels_populated(grafana_client):
        """Dashboard panels have data"""
        dashboard_uid = "saas-overview"
        dashboard = await grafana_client.get_dashboard(dashboard_uid)

        for panel in dashboard["dashboard"]["panels"]:
            # Query panel data source
            panel_data = await grafana_client.query_panel(dashboard_uid, panel["id"])
            assert len(panel_data) > 0

    async def test_dashboard_variables(grafana_client):
        """Dashboard variables populate correctly"""
        dashboard_uid = "saas-overview"
        variables = await grafana_client.get_variables(dashboard_uid)

        # Verify tenant_id variable has options
        tenant_var = variables["tenant_id"]
        assert len(tenant_var["options"]) > 0


class TestAlertRules:
    """Test Prometheus alert rules"""

    async def test_high_error_rate_alert(api_client, prometheus_client):
        """High error rate alert triggers"""
        # Generate errors
        for _ in range(100):
            await api_client.get("/api/v1/trigger-error")

        # Wait for alert evaluation
        await asyncio.sleep(70)  # 1m for condition + 1m for "for" duration + buffer

        # Verify alert fired
        alerts = await prometheus_client.get_alerts()
        assert any(a["labels"]["alertname"] == "HighErrorRate" for a in alerts)

    async def test_high_latency_alert(api_client, prometheus_client):
        """High latency alert triggers"""
        # Generate slow requests
        for _ in range(50):
            await api_client.get("/api/v1/slow-endpoint")

        # Wait for alert evaluation
        await asyncio.sleep(130)  # 2m for duration + buffer

        # Verify alert
        alerts = await prometheus_client.get_alerts()
        assert any(a["labels"]["alertname"] == "HighLatency" for a in alerts)

    async def test_alert_clears(api_client, prometheus_client):
        """Alert clears when condition resolves"""
        # Trigger alert (high error rate)
        for _ in range(100):
            await api_client.get("/api/v1/trigger-error")

        await asyncio.sleep(70)
        alerts_fired = await prometheus_client.get_alerts()
        assert len(alerts_fired) > 0

        # Stop errors, make successful requests
        for _ in range(100):
            await api_client.get("/api/v1/lattices")

        await asyncio.sleep(70)
        alerts_after = await prometheus_client.get_alerts()
        # Alert should clear
        assert len(alerts_after) < len(alerts_fired)


class TestWebhookAlerts:
    """Test webhook alert delivery"""

    async def test_webhook_triggered_on_alert(api_client, webhook_server, prometheus_client):
        """Webhook called when alert fires"""
        # Trigger alert
        for _ in range(100):
            await api_client.get("/api/v1/trigger-error")

        await asyncio.sleep(70)

        # Verify webhook received notification
        webhooks_received = webhook_server.get_received_webhooks()
        assert len(webhooks_received) > 0
        assert webhooks_received[0]["alert"] == "HighErrorRate"

    async def test_webhook_payload_format(webhook_server):
        """Webhook payload includes expected fields"""
        # (trigger alert, then check payload)
        webhook = webhook_server.get_received_webhooks()[0]

        assert "alert" in webhook
        assert "severity" in webhook["labels"]
        assert "annotations" in webhook
        assert "summary" in webhook["annotations"]

    async def test_webhook_retry_on_failure(api_client, webhook_server):
        """Webhook retries on failure"""
        # Configure webhook to fail
        webhook_server.fail_next_request()

        # Trigger alert
        # (implementation...)

        # Verify retry
        assert webhook_server.get_retry_count() > 0


class TestEndToEndMonitoring:
    """Test complete monitoring flow"""

    async def test_complete_alert_flow(api_client, prometheus_client, webhook_server):
        """Complete flow: metric → alert → webhook"""
        # 1. Generate condition (high error rate)
        for _ in range(100):
            await api_client.get("/api/v1/trigger-error")

        # 2. Wait for metric scrape + alert evaluation
        await asyncio.sleep(70)

        # 3. Verify metric in Prometheus
        error_rate = await prometheus_client.query('rate(http_requests_total{status="500"}[1m])')
        assert float(error_rate) > 0.05

        # 4. Verify alert fired
        alerts = await prometheus_client.get_alerts()
        assert any(a["labels"]["alertname"] == "HighErrorRate" for a in alerts)

        # 5. Verify webhook delivered
        webhooks = webhook_server.get_received_webhooks()
        assert len(webhooks) > 0

    async def test_multi_tenant_metrics_isolation(api_client):
        """Metrics isolated by tenant"""
        # Create requests from tenant A
        tenant_a_client = await create_authenticated_client("tenant_a@example.com")
        await tenant_a_client.get("/api/v1/lattices")

        # Create requests from tenant B
        tenant_b_client = await create_authenticated_client("tenant_b@example.com")
        await tenant_b_client.get("/api/v1/lattices")

        # Query metrics per tenant
        tenant_a_requests = await get_metric_value("http_requests_total", {"tenant_id": "tenant-a"})
        tenant_b_requests = await get_metric_value("http_requests_total", {"tenant_id": "tenant-b"})

        assert tenant_a_requests > 0
        assert tenant_b_requests > 0
        assert tenant_a_requests != tenant_b_requests  # Independent counts
```

### Estimated Test Count

- Prometheus Metrics: 4 tests
- Application Metrics: 3 tests
- Grafana Dashboards: 3 tests
- Alert Rules: 3 tests
- Webhook Alerts: 3 tests
- End-to-End: 2 tests

**Total**: 18 test cases

---

## Dependencies

### Infrastructure
- Prometheus server (localhost:9090)
- Grafana server (localhost:3000)
- Alertmanager (localhost:9093)
- Test webhook server (mock)

### Configuration Files
- `monitoring/prometheus.yml` - Prometheus configuration
- `monitoring/prometheus-rules.yml` - Alert rules
- `monitoring/grafana/dashboards/` - Dashboard JSON files

### Python Packages
- pytest
- pytest-asyncio
- httpx
- prometheus-client
- requests (for Prometheus/Grafana API)

### Existing Code
- `saas/api/metrics_instrumentation.py` - Metrics implementation
- `monitoring/` - Monitoring stack configuration

---

## Test Fixtures Required

### Prometheus Client Fixture
```python
@pytest.fixture
async def prometheus_client():
    """Client for Prometheus API"""
    return PrometheusClient(base_url="http://localhost:9090")
```

### Grafana Client Fixture
```python
@pytest.fixture
async def grafana_client():
    """Client for Grafana API"""
    return GrafanaClient(
        base_url="http://localhost:3000",
        api_key=os.getenv("GRAFANA_API_KEY")
    )
```

### Mock Webhook Server Fixture
```python
@pytest.fixture
async def webhook_server():
    """Mock webhook server for testing alert delivery"""
    server = MockWebhookServer()
    await server.start()
    yield server
    await server.stop()
```

---

## Out of Scope

- Prometheus/Grafana installation/configuration
- Long-term metric retention testing
- Dashboard UI testing (visual)
- Alertmanager routing logic
- Third-party integrations (PagerDuty, Slack)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Timing issues in alert tests | High | Medium | Use generous timeouts, idempotent checks |
| Metrics cardinality explosion | Low | High | Test with limited label values |
| Grafana API changes | Low | Medium | Version pin Grafana |
| Webhook delivery flakiness | Medium | Low | Retry logic, multiple attempts |

---

## Timeline

- **Day 1 AM**: Design monitoring test architecture (TDD creation)
- **Day 1 PM**: Implement Prometheus metrics tests
- **Day 2 AM**: Implement alert and webhook tests
- **Day 2 PM**: Implement Grafana and end-to-end tests
- **Day 3**: Timing tuning and flake reduction

---

## Definition of Done

- [ ] All 18 test cases implemented
- [ ] All tests passing reliably (< 10% flake rate)
- [ ] Monitoring stack validated end-to-end
- [ ] Dashboard queries verified
- [ ] Alert delivery confirmed
- [ ] Documentation complete
- [ ] Code reviewed by QA agent
- [ ] Production monitoring ready for deployment

---

## Related Documents

- **INSTRUMENTATION_COMPLETE.md**: Metrics implementation details
- **monitoring/prometheus-rules.yml**: Alert rule definitions
- **saas/api/metrics_instrumentation.py**: Metrics code

---

**PRD Approved By**: BMAD Product Manager Agent
**Ready for**: Architect Agent (TDD Creation)
**Status**: ✅ Ready for Implementation Planning

**Operational Readiness**: This test suite validates production monitoring is working before deployment.
