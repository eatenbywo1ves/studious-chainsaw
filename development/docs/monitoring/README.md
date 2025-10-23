# Monitoring Documentation

## Overview

This directory contains comprehensive documentation for the Catalytic SaaS monitoring infrastructure.

## Quick Links

- **[Monitoring Validation Report](MONITORING_VALIDATION_COMPLETE.md)** - Complete status report for Phase 5
- **[Validation Checklist](MONITORING_VALIDATION_CHECKLIST.md)** - Production readiness checklist
- **[Dashboard Guide](dashboard_guide.md)** - How to use Grafana dashboards
- **[Developer Workflow Dashboard](../../monitoring/grafana/dashboards/developer-workflow-dashboard.json)** - Real-time development monitoring (NEW)
- **[Metrics Catalog](metrics_catalog.md)** - Complete catalog of all metrics

## Alert Runbooks

Quick access to incident response runbooks:

| Alert | Severity | Runbook |
|-------|----------|---------|
| High API Latency | Warning | [runbooks/high_api_latency.md](runbooks/high_api_latency.md) |
| High Error Rate | Critical | [runbooks/high_error_rate.md](runbooks/high_error_rate.md) |
| Database Connection Pool | Critical | [runbooks/database_connection_pool.md](runbooks/database_connection_pool.md) |
| Redis Memory Pressure | Warning | [runbooks/redis_memory_pressure.md](runbooks/redis_memory_pressure.md) |
| Service Unavailable | Critical | [runbooks/service_unavailable.md](runbooks/service_unavailable.md) |
| GPU Memory Exhaustion | Critical | [runbooks/gpu_memory_exhaustion.md](runbooks/gpu_memory_exhaustion.md) |

## Quick Start

### Access Monitoring Services

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/changeme123!)
- **Alertmanager**: http://localhost:9093

### Run Validation Tests

```bash
cd C:/Users/Corbin/development/tests/monitoring
python test_prometheus_scraping.py
python test_grafana_dashboards.py
python test_alert_rules.py
```

Or run all tests:
```bash
./validate_monitoring.bat  # Windows
./validate_monitoring.sh   # Linux/Mac
```

### Start Monitoring Stack

```bash
cd C:/Users/Corbin/development/monitoring
docker-compose -f docker-compose.monitoring.yml up -d
```

### Check Service Health

```bash
# Prometheus
curl http://localhost:9090/-/healthy

# Grafana
curl http://localhost:3000/api/health

# Alertmanager
curl http://localhost:9093/-/healthy
```

## Documentation Structure

```
docs/monitoring/
├── README.md (this file)
├── MONITORING_VALIDATION_COMPLETE.md    # Complete status report
├── MONITORING_VALIDATION_CHECKLIST.md   # Production checklist
├── dashboard_guide.md                    # Dashboard user guide
├── metrics_catalog.md                    # Metrics reference
└── runbooks/                             # Alert runbooks
    ├── high_api_latency.md
    ├── high_error_rate.md
    ├── database_connection_pool.md
    ├── redis_memory_pressure.md
    ├── service_unavailable.md
    └── gpu_memory_exhaustion.md
```

## Key Metrics

### Application Metrics
- `http_requests_total` - API request counter
- `http_request_duration_seconds` - API latency histogram

### Security Metrics
- `encryption_errors_total` - Encryption failures
- `input_validation_failures_total` - Validation failures

### Database Metrics
- `database_connections_active` - Active connections
- `database_query_duration_seconds` - Query performance

### Cache Metrics
- `redis_memory_used_bytes` - Redis memory usage
- `cache_hits_total` / `cache_misses_total` - Cache efficiency

## Alert Severity Levels

- **Critical**: Immediate action required, service degradation likely
- **Warning**: Investigation needed, potential issues
- **Info**: Informational, no action required

## Getting Help

### During an Incident

1. Check the relevant runbook in `runbooks/`
2. Follow diagnosis steps
3. Execute resolution procedures
4. Escalate if needed (see runbook for escalation path)

### For General Questions

- Review [Dashboard Guide](dashboard_guide.md)
- Check [Metrics Catalog](metrics_catalog.md)
- Review [Validation Checklist](MONITORING_VALIDATION_CHECKLIST.md)

### Contact

- Backend Team: #backend-team
- Infrastructure Team: #infrastructure
- Security Team: #security-team
- On-call: PagerDuty rotation

## Developer Workflow Dashboard (NEW)

### Overview
The **Developer Workflow Dashboard** is a comprehensive Grafana dashboard designed to monitor development progress and system health in real-time. Unlike traditional ops dashboards, this combines performance, security, and workflow metrics in one unified view.

**Location**: `../../monitoring/grafana/dashboards/developer-workflow-dashboard.json`

### Key Features
- **13 Real-time Panels**: API performance, security, resources, and workflow metrics
- **10-second Auto-refresh**: Instant feedback during development
- **Developer-optimized Views**: Morning health check, deploy monitoring, debugging workflows
- **Integrated Metrics**: 60+ Prometheus metrics from all system components

### Quick Start

1. **Import Dashboard**:
   ```bash
   # Navigate to Grafana
   open http://localhost:3000
   # Click "+" → "Import" → Upload developer-workflow-dashboard.json
   ```

2. **Access Dashboard**: `/d/developer-workflow/developer-workflow-dashboard`

3. **Daily Usage**:
   - **Morning**: Quick health scan (top row panels all green?)
   - **Deploy**: Watch success rate, response times, error rates
   - **Debug**: Systematic approach via dashboard panels
   - **Evening**: Review ML scan progress, authentication activity

### Dashboard Panels

| Panel | What It Shows | Healthy Range |
|-------|---------------|---------------|
| **API Requests/Min** | Traffic volume | <100 req/min |
| **Success Rate** | 2xx response percentage | >99% |
| **Response Time** | p50/p95/p99 latencies | p99 < 1s |
| **Server Errors** | 5xx error rate | 0-10/min |
| **Rate Limit Blocks** | Security blocks | 0-5/min |
| **DB Connections** | Pool utilization | <90% max |
| **Cache Hit Ratio** | Cache effectiveness | >80% |
| **Memory Usage** | Component breakdown | Per component tracking |
| **Top 10 Endpoints** | API hotspots | Traffic distribution |
| **Authentication** | Login success/failures | Monitor for spikes |
| **ML Security** | Scan activity | Progress tracking |
| **Webhooks** | Delivery status | >95% success |
| **System Resources** | CPU/Memory/Disk | <70% each |

### Prometheus Queries Used

```promql
# API Request Rate
rate(http_requests_total[5m]) * 60

# Success Rate
(sum(rate(http_requests_total{status=~"2.."}[5m])) / sum(rate(http_requests_total[5m]))) * 100

# p99 Latency
histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) * 1000

# Cache Hit Ratio
(sum(rate(cache_hits_total[5m])) / (sum(rate(cache_hits_total[5m])) + sum(rate(cache_misses_total[5m])))) * 100
```

### Deployment Methods

**Method 1: Manual Import (Recommended for First Time)**
1. Grafana UI → "+" → "Import"
2. Upload `developer-workflow-dashboard.json`
3. Select Prometheus data source
4. Click "Import"

**Method 2: Docker Compose Provisioning**
```yaml
grafana:
  volumes:
    - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
```

**Method 3: Kubernetes ConfigMap**
```bash
kubectl create configmap grafana-developer-dashboard \
  --from-file=developer-workflow-dashboard.json \
  -n monitoring
```

### Troubleshooting

**"No Data" in Panels**:
```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify metrics endpoint
curl http://localhost:8000/metrics | grep http_requests_total

# Test Grafana data source
# Grafana UI → Configuration → Data Sources → Prometheus → Test
```

**Dashboard Not Updating**:
- Check auto-refresh (top-right): Should show "10s"
- Manually refresh: Click refresh icon
- Verify Prometheus: `curl http://localhost:9090/-/healthy`

### Pro Tips

1. **Use Multiple Monitors**: Dashboard on second monitor for continuous visibility
2. **Set Up Alerts**: Configure Prometheus alerts for critical thresholds
3. **Create Snapshots**: Before major changes for comparison
4. **Use Annotations**: Mark deployments to correlate with metric changes
5. **Customize Panels**: Add your most-used endpoints or custom metrics

### Benefits

✅ **Instant Visibility**: See system health at a glance
✅ **Proactive Monitoring**: Catch issues before users do
✅ **Data-Driven Decisions**: Optimize based on real metrics
✅ **Deployment Confidence**: Validate changes with metrics
✅ **Faster Debugging**: Systematic approach reduces MTTR

### Related Dashboards

- [Catalytic Overview Dashboard](../../saas/monitoring/grafana/dashboards/catalytic-overview-dashboard.json) - Business metrics
- [System Metrics Dashboard](../../monitoring/grafana/dashboards/system-metrics-dashboard.json) - Detailed system view
- **Developer Workflow Dashboard** - This dashboard (NEW)

---

## Recent Updates

- **2025-10-22**: Added Developer Workflow Dashboard for real-time development monitoring
- **2025-10-06**: Phase 5 complete - All runbooks and documentation created
- **2025-10-06**: Validation tests implemented
- **2025-10-06**: Comprehensive metrics catalog added

## Next Steps

See [MONITORING_VALIDATION_COMPLETE.md](MONITORING_VALIDATION_COMPLETE.md) for:
- Production deployment guide
- Known issues and limitations
- Future enhancements
- Team responsibilities

---

*Last updated: 2025-10-22*
