# Monitoring Documentation

## Overview

This directory contains comprehensive documentation for the Catalytic SaaS monitoring infrastructure.

## Quick Links

- **[Monitoring Validation Report](MONITORING_VALIDATION_COMPLETE.md)** - Complete status report for Phase 5
- **[Validation Checklist](MONITORING_VALIDATION_CHECKLIST.md)** - Production readiness checklist
- **[Dashboard Guide](dashboard_guide.md)** - How to use Grafana dashboards
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

## Recent Updates

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

*Last updated: 2025-10-06*
