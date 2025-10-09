# Monitoring Operations Guide

**Document Version:** 1.0
**Last Updated:** 2025-10-08
**Status:** Production Ready

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Monitoring Architecture](#monitoring-architecture)
3. [Infrastructure Components](#infrastructure-components)
4. [Grafana Dashboards](#grafana-dashboards)
5. [Alert Rules](#alert-rules)
6. [Health Checks](#health-checks)
7. [Metrics Catalog](#metrics-catalog)
8. [Alert Runbooks](#alert-runbooks)
9. [Troubleshooting](#troubleshooting)
10. [Compliance](#compliance)
11. [References](#references)

---

## Executive Summary

### Production Status

**Monitoring Stack:** ✅ **Fully Operational**

| Component | Status | Purpose | Version |
|-----------|--------|---------|---------|
| **Prometheus** | ✅ Active | Metrics collection & alerting | 2.45.0 |
| **Grafana** | ✅ Active | Visualization & dashboards | 10.0.0 |
| **Alertmanager** | ✅ Active | Alert routing & notifications | 0.25.0 |
| **Node Exporter** | ✅ Active | System metrics | 1.6.1 |
| **Redis Exporter** | ✅ Active | Cache metrics | 1.50.0 |
| **Postgres Exporter** | ✅ Active | Database metrics | 0.13.0 |

### Key Achievements

**Infrastructure:**
- ✅ 6 monitoring services deployed
- ✅ 30+ metrics collected (15s scrape interval)
- ✅ 30-day metric retention
- ✅ 100% target uptime

**Dashboards:**
- ✅ 2 production dashboards (29 panels total)
- ✅ System Metrics Dashboard (12 panels)
- ✅ Business Metrics Dashboard (17 panels)
- ✅ Template variables for filtering
- ✅ Geographic analytics with world map

**Alerting:**
- ✅ 18 alert rules configured
- ✅ 10 security alerts
- ✅ 7 performance alerts
- ✅ 1 operational alert
- ✅ Email/Slack/PagerDuty integration ready

**Validation:**
- ✅ 6 alert runbooks created
- ✅ 30+ automated test cases
- ✅ 100% alert rule coverage
- ✅ Compliance requirements met (PCI DSS, SOC 2, ISO 27001)

### Performance Targets

**System Performance:**
- API Response Time: <500ms (p95)
- Memory Efficiency: 28,571x vs traditional methods
- Processing Speed: 649x improvement
- Cache Hit Rate: >90%
- Error Rate: <0.1%

**Business Metrics:**
- MRR Growth: >15% monthly
- Customer Churn: <5% monthly
- Trial Conversion: >20%
- Payment Success: >98%
- CLV:CAC Ratio: >5:1

---

## Monitoring Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Monitoring Infrastructure                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Prometheus  │───▶│   Grafana    │    │ Alertmanager │      │
│  │  (Metrics)   │    │ (Dashboards) │◀───│   (Alerts)   │      │
│  └──────┬───────┘    └──────────────┘    └──────┬───────┘      │
│         │                                         │               │
│         │ Scrapes (15s interval)         Routes │               │
│         ▼                                         ▼               │
│  ┌──────────────────────────────────────────────────────┐       │
│  │                Metrics Exporters                      │       │
│  ├──────────┬──────────┬──────────┬───────────────────┤       │
│  │ App      │ Redis    │Postgres  │ Node  │ GPU       │       │
│  │/metrics  │Exporter  │Exporter  │Exporter│ Metrics  │       │
│  └──────────┴──────────┴──────────┴───────────────────┘       │
│         ▲        ▲         ▲          ▲         ▲              │
│         │        │         │          │         │              │
└─────────┼────────┼─────────┼──────────┼─────────┼──────────────┘
          │        │         │          │         │
    ┌─────┴──┐  ┌─┴──┐  ┌───┴────┐  ┌─┴────┐  ┌┴──────┐
    │ SaaS   │  │Redis│ │PostgreSQL│ │System│  │NVIDIA │
    │  API   │  └─────┘ └──────────┘ └──────┘  │ GPU   │
    └────────┘                                   └───────┘
```

### Data Flow

**1. Metrics Collection:**
```
Application exposes /metrics → Prometheus scrapes every 15s →
Stores time-series data → Recording rules pre-compute aggregations
```

**2. Visualization:**
```
Grafana queries Prometheus → Executes PromQL queries →
Renders dashboards → Updates every 10s
```

**3. Alerting:**
```
Prometheus evaluates alert rules → Fires alerts to Alertmanager →
Routes to appropriate receiver (Email/Slack/PagerDuty) →
Triggers incident response
```

### Network Topology

**Ports:**
- `9090` - Prometheus (metrics database)
- `3000` - Grafana (web UI)
- `9093` - Alertmanager (alert routing)
- `9100` - Node Exporter (system metrics)
- `9121` - Redis Exporter (cache metrics)
- `9187` - Postgres Exporter (database metrics)
- `8000` - Application `/metrics` endpoint

**Docker Network:**
- All services on `monitoring` bridge network
- Internal DNS resolution enabled
- No public exposure except Grafana (3000)

---

## Infrastructure Components

### 1. Prometheus

**Purpose:** Metrics collection, storage, and alerting engine

**Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s      # Scrape metrics every 15 seconds
  evaluation_interval: 15s  # Evaluate alert rules every 15 seconds
  external_labels:
    cluster: 'catalytic-prod'
    environment: 'production'

scrape_configs:
  # Application metrics
  - job_name: 'catalytic-saas'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['saas-api:8000']
        labels:
          service: 'api'
          team: 'backend'

  # Redis metrics
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
        labels:
          service: 'cache'

  # PostgreSQL metrics
  - job_name: 'postgresql'
    static_configs:
      - targets: ['postgres-exporter:9187']
        labels:
          service: 'database'

  # System metrics
  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
        labels:
          service: 'system'

# Alert rule files
rule_files:
  - 'prometheus-rules.yml'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

**Storage Configuration:**
```bash
# Command-line flags
--storage.tsdb.retention.time=30d  # Keep 30 days of metrics
--storage.tsdb.retention.size=50GB # Maximum disk usage
--storage.tsdb.path=/prometheus    # Data directory
--web.enable-lifecycle             # Enable hot reload
```

**Recording Rules:**
```yaml
# Pre-computed metrics for faster queries
groups:
  - name: api_recording_rules
    interval: 15s
    rules:
      # API request rate (per minute)
      - record: api:http_requests:rate1m
        expr: sum(rate(http_requests_total[1m]))

      # API error rate
      - record: api:http_requests:error_rate
        expr: sum(rate(http_requests_total{status=~"5.."}[1m])) / sum(rate(http_requests_total[1m]))

      # p95 API latency
      - record: api:http_request_duration:p95
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

      # p99 API latency
      - record: api:http_request_duration:p99
        expr: histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))

      # Database connection pool utilization
      - record: database:connection_pool:utilization
        expr: database_connections_active / database_connections_max

      # Redis hit rate
      - record: cache:redis:hit_rate
        expr: sum(rate(redis_keyspace_hits_total[5m])) / (sum(rate(redis_keyspace_hits_total[5m])) + sum(rate(redis_keyspace_misses_total[5m])))

      # Memory efficiency ratio
      - record: system:memory:efficiency_ratio
        expr: memory_optimization_ratio / 28571 * 100

      # Processing speed ratio
      - record: system:processing:speed_ratio
        expr: processing_speed_improvement / 649 * 100
```

**Health Checks:**
```bash
# Readiness
curl http://localhost:9090/-/ready

# Health
curl http://localhost:9090/-/healthy

# Targets status
curl http://localhost:9090/api/v1/targets

# Active alerts
curl http://localhost:9090/api/v1/alerts
```

---

### 2. Grafana

**Purpose:** Visualization and dashboard platform

**Data Sources:**
```yaml
# datasources.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false

  - name: Redis
    type: redis-datasource
    access: proxy
    url: redis:6379
    jsonData:
      client: standalone
      password: $REDIS_PASSWORD

  - name: PostgreSQL
    type: postgres
    url: postgresql:5432
    database: catalytic_db
    user: $DB_USER
    secureJsonData:
      password: $DB_PASSWORD
```

**Dashboard Provisioning:**
```yaml
# dashboard-provisioning.yml
apiVersion: 1

providers:
  - name: 'Catalytic Dashboards'
    orgId: 1
    folder: 'Production'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
      foldersFromFilesStructure: true
```

**Authentication:**
```ini
# grafana.ini
[auth]
disable_login_form = false
disable_signout_menu = false

[auth.basic]
enabled = true

[auth.anonymous]
enabled = false

[auth.google]
enabled = false  # Enable for production with OAuth
# client_id = YOUR_CLIENT_ID
# client_secret = YOUR_CLIENT_SECRET
# allowed_domains = yourcompany.com
```

**Security:**
```ini
[security]
admin_user = admin
admin_password = $GRAFANA_ADMIN_PASSWORD  # Change from default!
secret_key = $GRAFANA_SECRET_KEY
cookie_secure = true  # Enable in production with HTTPS
cookie_samesite = lax
allow_embedding = false

[snapshots]
external_enabled = false  # Disable public snapshots

[users]
allow_sign_up = false
allow_org_create = false
auto_assign_org = true
auto_assign_org_role = Viewer
```

**Health Check:**
```bash
curl http://localhost:3000/api/health
# Expected: {"commit":"...","database":"ok","version":"..."}
```

---

### 3. Alertmanager

**Purpose:** Alert routing and notification management

**Configuration:**
```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m

  # SMTP configuration for email alerts
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@catalyticcomputing.com'
  smtp_auth_username: 'alerts@catalyticcomputing.com'
  smtp_auth_password: '$SMTP_PASSWORD'
  smtp_require_tls: true

# Routing tree
route:
  # Default receiver for all alerts
  receiver: 'default'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s        # Wait for more alerts before grouping
  group_interval: 5m     # How often to send notifications for grouped alerts
  repeat_interval: 4h    # How often to re-send notifications

  # Route specific alerts to specific receivers
  routes:
    # Critical security alerts (immediate)
    - match:
        severity: critical
        category: security
      receiver: 'security-critical'
      group_wait: 10s
      group_interval: 1m
      repeat_interval: 30m
      continue: true  # Also send to default

    # Warning security alerts
    - match:
        severity: warning
        category: security
      receiver: 'security-warning'
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 2h

    # Performance alerts
    - match:
        category: performance
      receiver: 'performance-team'
      group_wait: 5m
      group_interval: 10m
      repeat_interval: 12h

    # Infrastructure alerts
    - match:
        category: infrastructure
      receiver: 'infrastructure-team'
      group_wait: 5m
      group_interval: 10m
      repeat_interval: 12h

# Inhibition rules (suppress alerts)
inhibit_rules:
  # Critical alerts suppress warning alerts
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']

  # Security alerts suppress performance alerts
  - source_match:
      category: 'security'
    target_match:
      category: 'performance'
    equal: ['instance']

# Alert receivers
receivers:
  # Default receiver
  - name: 'default'
    email_configs:
      - to: 'ops-team@catalytic.local'
        headers:
          Subject: '[ALERT] {{ .GroupLabels.alertname }}'
        send_resolved: true

  # Critical security alerts
  - name: 'security-critical'
    email_configs:
      - to: 'security-team@catalytic.local'
        headers:
          Subject: '[CRITICAL SECURITY] {{ .GroupLabels.alertname }}'
        send_resolved: true
    slack_configs:
      - api_url: '$SLACK_WEBHOOK_URL'
        channel: '#security-critical'
        title: '🚨 CRITICAL SECURITY ALERT'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}'
        send_resolved: true
    webhook_configs:
      - url: '$PAGERDUTY_WEBHOOK_URL'
        send_resolved: true

  # Warning security alerts
  - name: 'security-warning'
    email_configs:
      - to: 'security-team@catalytic.local'
        headers:
          Subject: '[WARNING] {{ .GroupLabels.alertname }}'
        send_resolved: true
    slack_configs:
      - api_url: '$SLACK_WEBHOOK_URL'
        channel: '#security-alerts'
        title: '⚠️ Security Warning'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
        send_resolved: true

  # Performance team
  - name: 'performance-team'
    email_configs:
      - to: 'performance@catalytic.local'
        headers:
          Subject: '[PERFORMANCE] {{ .GroupLabels.alertname }}'
        send_resolved: true

  # Infrastructure team
  - name: 'infrastructure-team'
    email_configs:
      - to: 'infra@catalytic.local'
        headers:
          Subject: '[INFRASTRUCTURE] {{ .GroupLabels.alertname }}'
        send_resolved: true
```

**Health Check:**
```bash
curl http://localhost:9093/-/healthy

# Check configuration
docker exec catalytic-alertmanager amtool config show

# Test alert
docker exec catalytic-alertmanager amtool alert add \
    --alertname="TestAlert" \
    --severity="warning"
```

---

### 4. Exporters

#### Node Exporter

**Purpose:** System-level metrics (CPU, memory, disk, network)

**Metrics Exposed:**
- `node_cpu_seconds_total` - CPU usage by mode
- `node_memory_MemTotal_bytes` - Total system memory
- `node_memory_MemAvailable_bytes` - Available memory
- `node_disk_io_time_seconds_total` - Disk I/O time
- `node_filesystem_avail_bytes` - Available disk space
- `node_network_receive_bytes_total` - Network RX bytes
- `node_network_transmit_bytes_total` - Network TX bytes

**Configuration:**
```yaml
node-exporter:
  image: prom/node-exporter:v1.6.1
  command:
    - '--path.procfs=/host/proc'
    - '--path.sysfs=/host/sys'
    - '--path.rootfs=/rootfs'
    - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
  volumes:
    - /proc:/host/proc:ro
    - /sys:/host/sys:ro
    - /:/rootfs:ro
  ports:
    - "9100:9100"
```

#### Redis Exporter

**Purpose:** Redis cache metrics

**Metrics Exposed:**
- `redis_up` - Redis connection status
- `redis_memory_used_bytes` - Memory usage
- `redis_keyspace_hits_total` - Cache hits
- `redis_keyspace_misses_total` - Cache misses
- `redis_connected_clients` - Active connections
- `redis_evicted_keys_total` - Evicted keys

**Configuration:**
```yaml
redis-exporter:
  image: oliver006/redis_exporter:v1.50.0
  environment:
    REDIS_ADDR: redis:6379
    REDIS_PASSWORD: $REDIS_PASSWORD
  ports:
    - "9121:9121"
```

#### PostgreSQL Exporter

**Purpose:** Database metrics

**Metrics Exposed:**
- `pg_up` - Database connection status
- `pg_stat_database_numbackends` - Active connections
- `pg_stat_database_tup_fetched` - Rows fetched
- `pg_stat_database_tup_returned` - Rows returned
- `pg_stat_database_xact_commit` - Committed transactions
- `pg_stat_activity_max_tx_duration` - Longest transaction

**Configuration:**
```yaml
postgres-exporter:
  image: prometheuscommunity/postgres-exporter:v0.13.0
  environment:
    DATA_SOURCE_NAME: "postgresql://$DB_USER:$DB_PASSWORD@postgresql:5432/$DB_NAME?sslmode=disable"
  ports:
    - "9187:9187"
```

---

## Grafana Dashboards

### 1. System Metrics Dashboard

**UID:** `catalytic-system-metrics`
**Refresh:** 10 seconds
**Panels:** 12 panels

#### Panel 1: API Response Time (p95 & p99)
```promql
# p95 latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# p99 latency
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))
```

**Thresholds:**
- Green: <500ms
- Yellow: 500ms-1000ms
- Red: >1000ms

#### Panel 2: API Request Rate
```promql
sum(rate(http_requests_total[1m])) by (status)
```

**Display:** Time series (stacked area chart)

#### Panel 3: GPU Utilization
```promql
nvidia_gpu_utilization_percent
```

**Thresholds:**
- Green: <80%
- Yellow: 80%-90%
- Red: >90%

#### Panel 4: Memory Efficiency Ratio
```promql
memory_optimization_ratio / 28571 * 100
```

**Target:** 100% (28,571x improvement)

#### Panel 5: Processing Speed Improvement
```promql
processing_speed_improvement / 649 * 100
```

**Target:** 100% (649x improvement)

#### Panel 6: Database Connection Pool
```promql
# Active connections
database_connections_active

# Waiting connections
database_connections_waiting

# Max connections
database_connections_max

# Utilization
database_connections_active / database_connections_max * 100
```

**Thresholds:**
- Green: <70%
- Yellow: 70%-90%
- Red: >90%

#### Panel 7: Redis Cache Hit Rate
```promql
sum(rate(redis_keyspace_hits_total[5m])) /
(sum(rate(redis_keyspace_hits_total[5m])) + sum(rate(redis_keyspace_misses_total[5m]))) * 100
```

**Target:** >90%

#### Panel 8: Error Rate
```promql
sum(rate(http_requests_total{status=~"5.."}[1m])) /
sum(rate(http_requests_total[1m])) * 100
```

**Thresholds:**
- Green: <0.1%
- Yellow: 0.1%-1%
- Red: >1%

#### Panel 9: System CPU Usage
```promql
100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
```

**Thresholds:**
- Green: <70%
- Yellow: 70%-85%
- Red: >85%

#### Panel 10: System Memory Usage
```promql
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
```

**Thresholds:**
- Green: <80%
- Yellow: 80%-90%
- Red: >90%

#### Panel 11: Disk Usage
```promql
(node_filesystem_size_bytes{fstype!="tmpfs"} - node_filesystem_avail_bytes{fstype!="tmpfs"}) / node_filesystem_size_bytes{fstype!="tmpfs"} * 100
```

**Thresholds:**
- Green: <75%
- Yellow: 75%-85%
- Red: >85%

#### Panel 12: Lattice Operations
```promql
# Lattice creation rate
rate(lattice_creations_total[5m])

# Active lattices
active_lattices_gauge

# Lattice creation duration (p95)
histogram_quantile(0.95, rate(lattice_creation_seconds_bucket[5m]))
```

**Template Variables:**
- `$environment` - Environment filter (prod/staging/dev)
- `$instance` - Instance selection
- `$time_range` - Time range selector

---

### 2. Business Metrics Dashboard

**UID:** `catalytic-business-metrics`
**Refresh:** 30 seconds
**Panels:** 17 panels

#### Panel 1: Monthly Recurring Revenue (MRR)
```sql
SELECT
    date_trunc('month', created_at) as month,
    SUM(amount) as mrr
FROM subscriptions
WHERE status = 'active'
GROUP BY month
ORDER BY month DESC
LIMIT 12;
```

**Display:** Time series (line chart with trend)

#### Panel 2: MRR Growth Rate
```sql
WITH monthly_mrr AS (
    SELECT
        date_trunc('month', created_at) as month,
        SUM(amount) as mrr
    FROM subscriptions
    WHERE status = 'active'
    GROUP BY month
)
SELECT
    month,
    mrr,
    (mrr - LAG(mrr) OVER (ORDER BY month)) / LAG(mrr) OVER (ORDER BY month) * 100 as growth_rate
FROM monthly_mrr
ORDER BY month DESC
LIMIT 6;
```

**Target:** >15% monthly growth

#### Panel 3: Annual Recurring Revenue (ARR)
```sql
SELECT SUM(amount) * 12 as arr
FROM subscriptions
WHERE status = 'active';
```

**Display:** Single stat with sparkline

#### Panel 4: Active Subscriptions
```sql
SELECT
    plan_type,
    COUNT(*) as count
FROM subscriptions
WHERE status = 'active'
GROUP BY plan_type;
```

**Display:** Pie chart

#### Panel 5: Customer Churn Rate
```sql
WITH monthly_stats AS (
    SELECT
        date_trunc('month', canceled_at) as month,
        COUNT(*) as churned,
        (SELECT COUNT(*) FROM subscriptions WHERE status = 'active' AND created_at < date_trunc('month', canceled_at)) as active_at_start
    FROM subscriptions
    WHERE status = 'canceled'
    GROUP BY month
)
SELECT
    month,
    churned::float / active_at_start * 100 as churn_rate
FROM monthly_stats
ORDER BY month DESC
LIMIT 6;
```

**Target:** <5% monthly churn

#### Panel 6: Trial Conversions
```sql
SELECT
    COUNT(CASE WHEN status = 'active' AND trial_end < NOW() THEN 1 END)::float /
    COUNT(CASE WHEN trial_start IS NOT NULL THEN 1 END) * 100 as conversion_rate
FROM subscriptions
WHERE created_at >= NOW() - INTERVAL '30 days';
```

**Target:** >20% conversion rate

#### Panel 7: New User Registrations
```promql
sum(increase(user_registrations_total[24h]))
```

**Display:** Time series (daily)

#### Panel 8: User Activation Rate
```sql
SELECT
    COUNT(CASE WHEN last_login IS NOT NULL THEN 1 END)::float /
    COUNT(*) * 100 as activation_rate
FROM users
WHERE created_at >= NOW() - INTERVAL '7 days';
```

**Target:** >80% within 7 days

#### Panel 9: API Usage by Plan Type
```promql
sum(increase(http_requests_total[1h])) by (plan_type)
```

**Display:** Stacked bar chart

#### Panel 10: Lattice Utilization
```sql
SELECT
    plan_type,
    AVG(lattice_count) as avg_lattices,
    MAX(lattice_count) as max_lattices
FROM user_stats
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY plan_type;
```

#### Panel 11: Payment Success Rate
```promql
sum(increase(stripe_payment_success_total[1h])) /
(sum(increase(stripe_payment_success_total[1h])) + sum(increase(stripe_payment_failed_total[1h]))) * 100
```

**Target:** >98%

#### Panel 12: Payment Failures
```promql
sum(increase(stripe_payment_failed_total[1h])) by (failure_reason)
```

**Display:** Table with failure reasons

#### Panel 13: Support Ticket Volume
```sql
SELECT
    status,
    COUNT(*) as count
FROM support_tickets
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY status;
```

#### Panel 14: Average Resolution Time
```sql
SELECT
    AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600) as avg_hours
FROM support_tickets
WHERE status = 'resolved'
  AND created_at >= NOW() - INTERVAL '30 days';
```

**Target:** <24 hours

#### Panel 15: Geographic User Distribution
```sql
SELECT
    country,
    COUNT(*) as user_count,
    latitude,
    longitude
FROM users
GROUP BY country, latitude, longitude;
```

**Display:** World map visualization

#### Panel 16: Customer Lifetime Value (CLV)
```sql
SELECT
    AVG(total_revenue) as avg_clv
FROM (
    SELECT
        user_id,
        SUM(amount) as total_revenue
    FROM payments
    WHERE status = 'succeeded'
    GROUP BY user_id
) as user_revenues;
```

#### Panel 17: Customer Acquisition Cost (CAC) & CLV:CAC Ratio
```sql
WITH metrics AS (
    SELECT
        (SELECT SUM(amount) FROM marketing_spend WHERE created_at >= NOW() - INTERVAL '30 days') as marketing_spend,
        (SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '30 days') as new_customers,
        (SELECT AVG(total_revenue) FROM (
            SELECT user_id, SUM(amount) as total_revenue
            FROM payments
            WHERE status = 'succeeded'
            GROUP BY user_id
        ) as revenues) as avg_clv
)
SELECT
    marketing_spend / NULLIF(new_customers, 0) as cac,
    avg_clv,
    avg_clv / NULLIF(marketing_spend / NULLIF(new_customers, 0), 0) as clv_cac_ratio
FROM metrics;
```

**Target:** CLV:CAC > 5:1

**Template Variables:**
- `$plan_type` - Filter by subscription plan
- `$time_range` - Time range selector (default: 30d)
- `$country` - Geographic filter

**Annotations:**
- Deployment events (from Prometheus)
- Marketing campaigns
- Product launches
- Incidents

---

## Alert Rules

### Security Alerts (10 rules)

#### 1. Critical Failed Login Rate
```yaml
- alert: CriticalFailedLoginRate
  expr: rate(http_requests_total{endpoint="/auth/login",status="401"}[1m]) > 50
  for: 1m
  labels:
    severity: critical
    category: security
    compliance: pci_dss_10.2.4
  annotations:
    summary: "Critical rate of failed login attempts"
    description: "{{ $value | humanize }} failed logins per minute (threshold: 50/min)"
    remediation: "Check for brute force attack. Review source IPs. Consider IP blocking."
    runbook_url: "https://docs.catalytic.local/runbooks/failed_logins"
```

#### 2. High Failed Login Rate
```yaml
- alert: HighFailedLoginRate
  expr: rate(http_requests_total{endpoint="/auth/login",status="401"}[5m]) > 10
  for: 5m
  labels:
    severity: warning
    category: security
    compliance: pci_dss_10.2.4
  annotations:
    summary: "High rate of failed login attempts"
    description: "{{ $value | humanize }} failed logins per minute over 5 minutes"
    remediation: "Monitor for patterns. Prepare for potential escalation."
```

#### 3. SQL Injection Attempt
```yaml
- alert: SQLInjectionAttempt
  expr: rate(input_validation_failures_total{failure_type="sql_injection"}[5m]) > 0
  for: 1m
  labels:
    severity: critical
    category: security
    compliance: pci_dss_6.5.1
  annotations:
    summary: "SQL injection attempt detected"
    description: "{{ $value | humanize }} SQL injection patterns detected"
    remediation: "Block source IP immediately. Review WAF rules."
```

#### 4. Encryption Failure Rate
```yaml
- alert: EncryptionFailureRate
  expr: rate(encryption_errors_total[5m]) > 1
  for: 5m
  labels:
    severity: critical
    category: security
    compliance: pci_dss_3.x
  annotations:
    summary: "High encryption failure rate"
    description: "{{ $value | humanize }} encryption errors per second"
    remediation: "Check encryption service health. Verify key availability."
```

#### 5. Decryption Failure Rate
```yaml
- alert: DecryptionFailureRate
  expr: rate(decryption_errors_total[5m]) > 1
  for: 5m
  labels:
    severity: critical
    category: security
    compliance: pci_dss_3.x
  annotations:
    summary: "High decryption failure rate"
    description: "{{ $value | humanize }} decryption errors per second"
    remediation: "Check key rotation status. Verify database integrity."
```

#### 6. Rate Limit Exceeded
```yaml
- alert: RateLimitExceeded
  expr: rate(http_requests_total{status="429"}[5m]) > 10
  for: 5m
  labels:
    severity: warning
    category: security
  annotations:
    summary: "High rate of rate-limited requests"
    description: "{{ $value | humanize }} requests per minute being rate-limited"
    remediation: "Identify source. Check for API abuse."
```

#### 7. Unauthorized API Access
```yaml
- alert: UnauthorizedAPIAccess
  expr: rate(http_requests_total{status="403"}[5m]) > 10
  for: 5m
  labels:
    severity: warning
    category: security
    compliance: pci_dss_10.2.2
  annotations:
    summary: "High rate of unauthorized access attempts"
    description: "{{ $value | humanize }} 403 responses per minute"
    remediation: "Review access patterns. Check for compromised credentials."
```

#### 8. Input Validation Failures
```yaml
- alert: HighInputValidationFailures
  expr: rate(input_validation_failures_total[5m]) > 20
  for: 5m
  labels:
    severity: warning
    category: security
    compliance: pci_dss_6.5.1
  annotations:
    summary: "High input validation failure rate"
    description: "{{ $value | humanize }} validation failures per minute"
    remediation: "Check for malformed requests. Investigate potential attack."
```

#### 9. JWT Token Errors
```yaml
- alert: JWTTokenErrors
  expr: rate(jwt_verification_errors_total[5m]) > 5
  for: 5m
  labels:
    severity: warning
    category: security
  annotations:
    summary: "High JWT token error rate"
    description: "{{ $value | humanize }} JWT errors per minute"
    remediation: "Check token expiration. Verify signing key."
```

#### 10. Password Reset Abuse
```yaml
- alert: PasswordResetAbuse
  expr: rate(password_reset_requests_total[10m]) > 50
  for: 10m
  labels:
    severity: warning
    category: security
  annotations:
    summary: "Unusually high password reset request rate"
    description: "{{ $value | humanize }} password reset requests per minute"
    remediation: "Check for account enumeration attack. Implement CAPTCHA."
```

---

### Performance Alerts (7 rules)

#### 1. High API Latency
```yaml
- alert: HighAPILatency
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
  for: 5m
  labels:
    severity: warning
    category: performance
  annotations:
    summary: "High API response time (p95)"
    description: "p95 latency is {{ $value | humanize }}s (threshold: 0.5s)"
    remediation: "Check database queries. Review slow endpoints."
    runbook_url: "https://docs.catalytic.local/runbooks/high_api_latency"
```

#### 2. Critical API Latency
```yaml
- alert: CriticalAPILatency
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
  for: 2m
  labels:
    severity: critical
    category: performance
  annotations:
    summary: "Critical API response time (p95)"
    description: "p95 latency is {{ $value | humanize }}s (threshold: 1s)"
    remediation: "Immediate action required. Check database and cache."
```

#### 3. High Error Rate
```yaml
- alert: HighErrorRate
  expr: sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) > 0.01
  for: 5m
  labels:
    severity: critical
    category: performance
  annotations:
    summary: "High HTTP 5xx error rate"
    description: "Error rate is {{ $value | humanizePercentage }} (threshold: 1%)"
    remediation: "Check application logs. Review recent deployments."
    runbook_url: "https://docs.catalytic.local/runbooks/high_error_rate"
```

#### 4. Database Connection Pool Exhaustion
```yaml
- alert: DatabaseConnectionPoolExhaustion
  expr: database_connections_active / database_connections_max > 0.9
  for: 5m
  labels:
    severity: critical
    category: performance
  annotations:
    summary: "Database connection pool near exhaustion"
    description: "Connection pool {{ $value | humanizePercentage }} utilized (threshold: 90%)"
    remediation: "Check for connection leaks. Scale database connections."
    runbook_url: "https://docs.catalytic.local/runbooks/database_connection_pool"
```

#### 5. Redis Memory High
```yaml
- alert: RedisMemoryHigh
  expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.9
  for: 10m
  labels:
    severity: warning
    category: performance
  annotations:
    summary: "Redis memory usage high"
    description: "Redis memory {{ $value | humanizePercentage }} full (threshold: 90%)"
    remediation: "Review cache eviction policy. Consider scaling."
    runbook_url: "https://docs.catalytic.local/runbooks/redis_memory_pressure"
```

#### 6. Low Cache Hit Rate
```yaml
- alert: LowCacheHitRate
  expr: sum(rate(redis_keyspace_hits_total[5m])) / (sum(rate(redis_keyspace_hits_total[5m])) + sum(rate(redis_keyspace_misses_total[5m]))) < 0.8
  for: 15m
  labels:
    severity: warning
    category: performance
  annotations:
    summary: "Low cache hit rate"
    description: "Cache hit rate is {{ $value | humanizePercentage }} (threshold: 80%)"
    remediation: "Review cache strategy. Check TTL settings."
```

#### 7. GPU Memory Exhaustion
```yaml
- alert: GPUMemoryExhaustion
  expr: nvidia_gpu_memory_used_bytes / nvidia_gpu_memory_total_bytes > 0.95
  for: 5m
  labels:
    severity: critical
    category: performance
  annotations:
    summary: "GPU memory near exhaustion"
    description: "GPU memory {{ $value | humanizePercentage }} full (threshold: 95%)"
    remediation: "Reduce batch sizes. Optimize model loading."
    runbook_url: "https://docs.catalytic.local/runbooks/gpu_memory_exhaustion"
```

---

### Infrastructure Alerts (1 rule)

#### 1. Disk Space Low
```yaml
- alert: DiskSpaceLow
  expr: (node_filesystem_avail_bytes{fstype!="tmpfs"} / node_filesystem_size_bytes{fstype!="tmpfs"}) < 0.15
  for: 10m
  labels:
    severity: warning
    category: infrastructure
  annotations:
    summary: "Low disk space"
    description: "Only {{ $value | humanizePercentage }} disk space remaining (threshold: 15%)"
    remediation: "Clean up old logs. Extend disk volume."
```

---

## Health Checks

### Application Health Endpoint

**Endpoint:** `GET /health`

**Implementation:**
```python
from fastapi import FastAPI, Response
from sqlalchemy import text
import redis

app = FastAPI()

@app.get("/health")
async def health_check():
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {}
    }

    # Check database
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        health_status["services"]["database"] = "connected"
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["services"]["database"] = "error"
        health_status["error"] = str(e)

    # Check Redis
    try:
        redis_client.ping()
        health_status["services"]["redis"] = "connected"
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["services"]["redis"] = "error"
        if "error" not in health_status:
            health_status["error"] = str(e)

    status_code = 200 if health_status["status"] == "healthy" else 503
    return Response(
        content=json.dumps(health_status),
        media_type="application/json",
        status_code=status_code
    )
```

**Usage:**
```bash
# Quick check
curl http://localhost:8000/health

# With failure on unhealthy
curl -f http://localhost:8000/health || exit 1
```

---

### External Monitoring Services

#### 1. UptimeRobot (Recommended - Free)

**Setup:**
1. Visit: https://uptimerobot.com/
2. Create free account (50 monitors)
3. Add Monitor:
   - Type: HTTP(s)
   - URL: https://api.catalyticcomputing.com/health
   - Interval: 5 minutes
   - Expected Response: "healthy"
   - Alert contacts: Your email/SMS

**Features:**
- 5-minute checks
- Email/SMS/Slack alerts
- Public status page
- SSL certificate monitoring
- Response time tracking

**Cost:** Free (50 monitors)

#### 2. StatusCake (Free Alternative)

**Setup:**
1. Visit: https://www.statuscake.com/
2. Create free account
3. Add Test:
   - Type: HTTP
   - URL: https://api.catalyticcomputing.com/health
   - Interval: 5 minutes
   - Check string: "healthy"

**Features:**
- Free unlimited checks
- 5-minute interval
- SSL monitoring
- Public status page

**Cost:** Free (limited features)

---

### Error Tracking with Sentry

**Setup:**

1. Create account: https://sentry.io/signup/
2. Create project (Python/FastAPI)
3. Copy DSN

**Configuration:**
```bash
# .env.production
SENTRY_DSN=https://xxxxx@sentry.io/xxxxx
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.1  # 10% of transactions
```

**Integration:**
```python
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

if os.getenv("SENTRY_DSN"):
    sentry_sdk.init(
        dsn=os.getenv("SENTRY_DSN"),
        environment=os.getenv("SENTRY_ENVIRONMENT", "production"),
        traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1")),
        integrations=[FastApiIntegration()]
    )
```

**Cost:** Free (5K errors/month), $26/mo for 50K errors

---

## Metrics Catalog

### Application Metrics

**HTTP Requests:**
```prometheus
# Total HTTP requests
http_requests_total{method, endpoint, status}

# Request duration
http_request_duration_seconds{method, endpoint}

# Request size
http_request_size_bytes{method, endpoint}

# Response size
http_response_size_bytes{method, endpoint}
```

**Security Metrics:**
```prometheus
# Encryption operations
encryption_operations_total{operation_type}
encryption_errors_total{error_type}

# Validation
input_validation_failures_total{failure_type}

# Authentication
jwt_verification_errors_total{error_type}
password_reset_requests_total
```

**Business Metrics:**
```prometheus
# User registrations
user_registrations_total

# Subscriptions
subscription_creations_total{plan_type}
subscription_cancellations_total{plan_type}

# Payments
stripe_payment_success_total
stripe_payment_failed_total{failure_reason}

# Lattice operations
lattice_creations_total{dimensions}
lattice_creation_seconds{dimensions}
active_lattices_gauge
```

### Database Metrics

```prometheus
# Connections
database_connections_active
database_connections_waiting
database_connections_max

# Queries
database_query_duration_seconds
database_queries_total{query_type}

# Transactions
database_transactions_total{result}
database_transaction_duration_seconds
```

### Cache Metrics

```prometheus
# Memory
redis_memory_used_bytes
redis_memory_max_bytes

# Operations
redis_keyspace_hits_total
redis_keyspace_misses_total
redis_commands_processed_total

# Connections
redis_connected_clients
```

### System Metrics

```prometheus
# CPU
node_cpu_seconds_total{mode}

# Memory
node_memory_MemTotal_bytes
node_memory_MemAvailable_bytes

# Disk
node_filesystem_size_bytes
node_filesystem_avail_bytes
node_disk_io_time_seconds_total

# Network
node_network_receive_bytes_total
node_network_transmit_bytes_total
```

---

## Alert Runbooks

### 1. High API Latency

**Alert:** `HighAPILatency` (p95 > 500ms)
**Severity:** Warning
**Category:** Performance

**Immediate Actions (< 5 min):**
1. Check Grafana System Metrics dashboard
2. Identify slow endpoints:
   ```promql
   topk(5, histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) by (endpoint))
   ```
3. Check database connection pool utilization
4. Check Redis hit rate

**Short-term Actions (< 1 hour):**
1. Review slow queries in PostgreSQL logs:
   ```sql
   SELECT query, mean_exec_time, calls
   FROM pg_stat_statements
   ORDER BY mean_exec_time DESC
   LIMIT 10;
   ```
2. Add database indexes if needed
3. Increase cache TTL for frequently accessed data
4. Scale application instances if CPU > 80%

**Long-term Actions:**
- Implement query optimization
- Add database read replicas
- Implement request caching
- Consider CDN for static assets

**Escalation:** Backend team → Infrastructure team (if > 1 hour)

---

### 2. High Error Rate

**Alert:** `HighErrorRate` (error rate > 1%)
**Severity:** Critical
**Category:** Performance

**Immediate Actions (< 5 min):**
1. Check application logs:
   ```bash
   sudo journalctl -u catalytic-saas -n 100 | grep ERROR
   ```
2. Check recent deployments (rollback if needed)
3. Verify database and Redis connectivity
4. Check system resources (CPU, memory, disk)

**Emergency Rollback:**
```bash
# Docker
docker service rollback catalytic-saas

# Git + systemd
git checkout <previous-commit>
sudo systemctl restart catalytic-saas
```

**Short-term Actions:**
1. Identify error patterns:
   ```promql
   sum(rate(http_requests_total{status=~"5.."}[5m])) by (endpoint, status)
   ```
2. Fix critical bugs
3. Deploy hotfix if needed
4. Monitor error rate for 30 minutes

**Communication:**
- Post incident in #incidents Slack channel
- Update status page if user-facing
- Send email to affected customers if necessary

**Escalation:** On-call engineer → Backend lead (immediate)

---

### 3. Database Connection Pool Exhaustion

**Alert:** `DatabaseConnectionPoolExhaustion` (> 90% utilization)
**Severity:** Critical
**Category:** Performance

**Immediate Actions (< 5 min):**
1. Check active connections:
   ```sql
   SELECT count(*), state
   FROM pg_stat_activity
   GROUP BY state;
   ```
2. Identify long-running queries:
   ```sql
   SELECT pid, now() - query_start as duration, query
   FROM pg_stat_activity
   WHERE state = 'active'
   ORDER BY duration DESC;
   ```
3. Kill problematic queries if necessary:
   ```sql
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE pid = <PID>;
   ```

**Connection Leak Detection:**
```python
# Check for unclosed connections in code
# Good pattern:
with SessionLocal() as db:
    result = db.query(User).all()
    # Connection auto-closed

# Bad pattern (causes leaks):
db = SessionLocal()
result = db.query(User).all()
# Missing db.close()
```

**Short-term Actions:**
1. Increase connection pool size temporarily:
   ```python
   engine = create_engine(
       DATABASE_URL,
       pool_size=20,  # Increase from 10
       max_overflow=40  # Increase from 20
   )
   ```
2. Implement PgBouncer for connection pooling
3. Add connection timeout configuration

**Long-term Actions:**
- Audit codebase for connection leaks
- Implement connection pool monitoring
- Add automatic connection cleanup
- Consider database scaling

---

### 4. Redis Memory Pressure

**Alert:** `RedisMemoryHigh` (> 90% memory)
**Severity:** Warning
**Category:** Performance

**Immediate Actions:**
1. Check memory usage:
   ```bash
   redis-cli -a $REDIS_PASSWORD INFO memory
   ```
2. Check keyspace size:
   ```bash
   redis-cli -a $REDIS_PASSWORD INFO keyspace
   ```
3. Review eviction policy:
   ```bash
   redis-cli -a $REDIS_PASSWORD CONFIG GET maxmemory-policy
   ```

**Data Cleanup:**
```bash
# Find large keys
redis-cli -a $REDIS_PASSWORD --bigkeys

# Set aggressive eviction policy temporarily
redis-cli -a $REDIS_PASSWORD CONFIG SET maxmemory-policy allkeys-lru
```

**Long-term Actions:**
- Implement key expiration (TTL)
- Use Redis data structures efficiently
- Consider Redis clustering
- Implement cache tiering (Redis + disk cache)

---

### 5. Service Unavailable

**Alert:** `ServiceUnavailable` (health check failures)
**Severity:** Critical
**Category:** Infrastructure

**Immediate Actions:**
1. Check service status:
   ```bash
   sudo systemctl status catalytic-saas
   docker service ps catalytic-saas
   ```
2. Check service logs:
   ```bash
   sudo journalctl -u catalytic-saas -n 100
   docker service logs catalytic-saas --tail 100
   ```
3. Check system resources:
   ```bash
   htop
   df -h
   ```

**Service Restart:**
```bash
# Systemd
sudo systemctl restart catalytic-saas

# Docker Swarm
docker service update --force catalytic-saas
```

**Escalation:** Infrastructure team (immediate)

---

### 6. GPU Memory Exhaustion

**Alert:** `GPUMemoryExhaustion` (> 95% GPU memory)
**Severity:** Critical
**Category:** Performance

**Immediate Actions:**
1. Check GPU status:
   ```bash
   nvidia-smi
   ```
2. Check GPU processes:
   ```bash
   nvidia-smi pmon
   ```
3. Reduce batch sizes temporarily

**Memory Optimization:**
```python
# Clear PyTorch cache
import torch
torch.cuda.empty_cache()

# Enable gradient checkpointing
model.gradient_checkpointing_enable()

# Use FP16 instead of FP32
model.half()

# Reduce batch size
BATCH_SIZE = BATCH_SIZE // 2
```

**Long-term Actions:**
- Implement model quantization
- Use gradient accumulation
- Add GPU memory monitoring
- Consider multi-GPU deployment

---

## Troubleshooting

### Prometheus Not Scraping Targets

**Symptoms:**
- Targets showing "DOWN" in Prometheus UI
- No data in Grafana dashboards

**Diagnosis:**
```bash
# Check target status
curl http://localhost:9090/api/v1/targets | jq

# Check Prometheus logs
docker logs catalytic-prometheus

# Test metrics endpoint manually
curl http://saas-api:8000/metrics
```

**Solutions:**
1. Verify service is running and exposing /metrics
2. Check Docker network connectivity
3. Verify service name in prometheus.yml
4. Reload Prometheus configuration:
   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```

---

### Grafana Not Showing Data

**Symptoms:**
- Dashboards show "No data"
- Queries return empty results

**Diagnosis:**
1. Test Prometheus data source:
   - Grafana → Configuration → Data Sources → Prometheus → Test
2. Check time range (adjust to last 15 minutes)
3. Verify metric exists in Prometheus:
   ```bash
   curl 'http://localhost:9090/api/v1/query?query=up'
   ```

**Solutions:**
1. Fix Prometheus URL (should be `http://prometheus:9090`)
2. Adjust time range
3. Check if metrics are being scraped
4. Restart Grafana:
   ```bash
   docker restart catalytic-grafana
   ```

---

### Alerts Not Firing

**Symptoms:**
- No alerts despite metric thresholds exceeded
- Alertmanager shows no active alerts

**Diagnosis:**
```bash
# Check alert rules in Prometheus
curl http://localhost:9090/api/v1/rules | jq

# Check Alertmanager configuration
docker exec catalytic-alertmanager amtool config show

# Check Alertmanager logs
docker logs catalytic-alertmanager
```

**Solutions:**
1. Verify alert expression is correct
2. Check `for` duration (alert fires after duration)
3. Reload Prometheus configuration:
   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```
4. Test alert manually:
   ```bash
   docker exec catalytic-alertmanager amtool alert add \
       --alertname="TestAlert" \
       --severity="warning"
   ```

---

### High Prometheus Memory Usage

**Symptoms:**
- Prometheus container using >4GB memory
- System slow or unresponsive

**Solutions:**
1. Reduce retention time:
   ```yaml
   prometheus:
     command:
       - '--storage.tsdb.retention.time=15d'  # Reduce from 30d
       - '--storage.tsdb.retention.size=10GB'
   ```
2. Reduce scrape interval:
   ```yaml
   global:
     scrape_interval: 30s  # Increase from 15s
   ```
3. Remove unnecessary exporters
4. Implement Prometheus federation or Thanos

---

## Compliance

### PCI DSS Requirements

**Requirement 10 - Logging and Monitoring:**

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| 10.2.2 - Track unauthorized access attempts | `UnauthorizedAPIAccess` alert | ✅ Complete |
| 10.2.4 - Track authentication events | `HighFailedLoginRate` alert | ✅ Complete |
| 10.6 - Review logs and security events daily | Grafana dashboards | ✅ Complete |

**Requirement 6.5.1 - Input Validation:**
- ✅ Track validation failures (`HighInputValidationFailures` alert)
- ✅ Monitor for injection attacks (`SQLInjectionAttempt` alert)

**Requirement 3.x - Data Encryption:**
- ✅ Monitor encryption operations (`EncryptionFailureRate` alert)
- ✅ Monitor decryption operations (`DecryptionFailureRate` alert)

---

### SOC 2 Compliance

**CC7.2 - System Monitoring:**
- ✅ Continuous monitoring of system performance
- ✅ Real-time alerting for anomalies
- ✅ Audit trail of security events
- ✅ Automated incident response

**CC7.3 - Evaluation and Response:**
- ✅ Alert runbooks for incident response
- ✅ Escalation procedures documented
- ✅ Regular review of monitoring effectiveness

---

### ISO 27001

**A.12.4 - Logging and Monitoring:**
- ✅ Security event logging
- ✅ Log review and analysis
- ✅ Clock synchronization (NTP)
- ✅ Protection of log information

**A.16.1 - Management of Information Security Incidents:**
- ✅ Incident detection mechanisms
- ✅ Incident response procedures
- ✅ Incident communication channels

---

### GDPR

**Article 32 - Security of Processing:**
- ✅ Monitor for data breaches
- ✅ Track encryption failures
- ✅ Alert on unauthorized access
- ✅ Maintain audit logs (30 days)

---

## References

### Source Documentation

**Monitoring Deployment:**
- `C:\Users\Corbin\development\monitoring\MONITORING_DEPLOYMENT_GUIDE.md`
  - Prometheus + Grafana stack deployment
  - Configuration, instrumentation, dashboards
  - Security and compliance

**Monitoring Guide:**
- `C:\Users\Corbin\development\saas\MONITORING_GUIDE.md`
  - Health checks and external monitoring
  - Error tracking and logging
  - Performance and cloud monitoring

**Validation Report:**
- `C:\Users\Corbin\development\docs\monitoring\MONITORING_VALIDATION_COMPLETE.md`
  - Phase 5 completion report
  - Validation scripts and runbooks
  - Testing and compliance

**Grafana Dashboards:**
- `C:\Users\Corbin\development\docs\reports\GRAFANA_DASHBOARDS_SUMMARY.md`
  - System and business metrics dashboards
  - Deployment automation

### Configuration Files

**Docker Compose:**
- `C:\Users\Corbin\development\monitoring\docker-compose.monitoring.yml`

**Prometheus:**
- `C:\Users\Corbin\development\monitoring\prometheus.yml`
- `C:\Users\Corbin\development\monitoring\prometheus-rules.yml`

**Alertmanager:**
- `C:\Users\Corbin\development\monitoring\alertmanager.yml`

**Grafana:**
- `C:\Users\Corbin\development\monitoring\grafana\dashboards\system-metrics-dashboard.json`
- `C:\Users\Corbin\development\monitoring\grafana\dashboards\business-metrics-dashboard.json`
- `C:\Users\Corbin\development\monitoring\grafana\provisioning\dashboards\dashboard-provisioning.yml`
- `C:\Users\Corbin\development\monitoring\grafana\provisioning\datasources\datasources.yml`

### Deployment Scripts

**Dashboard Deployment:**
- `C:\Users\Corbin\development\scripts\deploy-grafana-dashboards.py`
- `C:\Users\Corbin\development\scripts\deploy-dashboards.sh`
- `C:\Users\Corbin\development\scripts\deploy-dashboards.bat`

**Monitoring Setup:**
- `C:\Users\Corbin\development\scripts\setup-monitoring.py`
- `C:\Users\Corbin\development\scripts\validate-dashboards.py`
- `C:\Users\Corbin\development\scripts\test-deployment.py`

### Validation Tests

**Test Suites:**
- `C:\Users\Corbin\development\tests\monitoring\test_prometheus_scraping.py`
- `C:\Users\Corbin\development\tests\monitoring\test_grafana_dashboards.py`
- `C:\Users\Corbin\development\tests\monitoring\test_alert_rules.py`

**Test Runners:**
- `C:\Users\Corbin\development\tests\monitoring\validate_monitoring.bat`
- `C:\Users\Corbin\development\tests\monitoring\validate_monitoring.sh`

### Alert Runbooks

- `C:\Users\Corbin\development\docs\monitoring\runbooks\high_api_latency.md`
- `C:\Users\Corbin\development\docs\monitoring\runbooks\high_error_rate.md`
- `C:\Users\Corbin\development\docs\monitoring\runbooks\database_connection_pool.md`
- `C:\Users\Corbin\development\docs\monitoring\runbooks\redis_memory_pressure.md`
- `C:\Users\Corbin\development\docs\monitoring\runbooks\service_unavailable.md`
- `C:\Users\Corbin\development\docs\monitoring\runbooks\gpu_memory_exhaustion.md`

### Additional Documentation

- `C:\Users\Corbin\development\docs\monitoring\dashboard_guide.md`
- `C:\Users\Corbin\development\docs\monitoring\metrics_catalog.md`
- `C:\Users\Corbin\development\docs\monitoring\MONITORING_VALIDATION_CHECKLIST.md`

### Related Guides

- Security Master Guide: `development/docs/guides/SECURITY_MASTER_GUIDE.md`
- Testing Guide: `development/docs/guides/TESTING_GUIDE.md`
- Redis Production Guide: `development/docs/guides/REDIS_PRODUCTION_GUIDE.md`
- GPU Acceleration Guide: `development/docs/guides/GPU_ACCELERATION_GUIDE.md`
- BMAD Master Guide: `development/docs/guides/BMAD_MASTER_GUIDE.md`
- MCP Production Guide: `development/docs/guides/MCP_PRODUCTION_GUIDE.md`

---

## Quick Reference Commands

**Start monitoring stack:**
```bash
cd C:/Users/Corbin/development/monitoring
docker-compose -f docker-compose.monitoring.yml up -d
```

**Check services:**
```bash
docker-compose -f docker-compose.monitoring.yml ps
```

**View logs:**
```bash
docker-compose -f docker-compose.monitoring.yml logs -f
```

**Stop monitoring stack:**
```bash
docker-compose -f docker-compose.monitoring.yml down
```

**Run validation:**
```bash
cd C:/Users/Corbin/development/tests/monitoring
./validate_monitoring.bat  # Windows
./validate_monitoring.sh   # Linux/Mac
```

**Access dashboards:**
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/changeme123!)
- Alertmanager: http://localhost:9093

**Reload Prometheus configuration:**
```bash
curl -X POST http://localhost:9090/-/reload
```

**Test alert:**
```bash
docker exec catalytic-alertmanager amtool alert add \
    --alertname="TestAlert" \
    --severity="warning"
```

---

**End of Monitoring Operations Guide**

*This guide consolidates:*
- *MONITORING_DEPLOYMENT_GUIDE.md (729 lines)*
- *MONITORING_GUIDE.md (664 lines)*
- *MONITORING_VALIDATION_COMPLETE.md (816 lines)*
- *GRAFANA_DASHBOARDS_SUMMARY.md (208 lines)*

*Total source material: 2,417 lines consolidated into comprehensive production guide*

---

**Document Status:** Production Ready
**Last Validated:** 2025-10-08
**Maintained By:** Operations Team
**Next Review:** 2025-11-08 (Monthly)
