# Kubernetes Monitoring Stack Documentation

## Overview

This monitoring stack provides complete observability for the Catalytic Computing system deployed on Kubernetes. It includes:

- **Prometheus**: Time-series metrics collection and storage
- **Grafana**: Visualization and dashboarding
- **AlertManager**: Alert routing and notification
- **Node Exporter**: System-level metrics from cluster nodes

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Prometheus  │──│   Grafana    │  │ AlertManager │  │
│  │   (Metrics)  │  │ (Dashboards) │  │   (Alerts)   │  │
│  └──────┬───────┘  └──────────────┘  └──────┬───────┘  │
│         │                                     │          │
│         ├─────────────────┬───────────────────┤          │
│         ▼                 ▼                   ▼          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Webhook    │  │  Catalytic   │  │     Node     │  │
│  │   System     │  │  Computing   │  │   Exporter   │  │
│  │  (Port 9090) │  │ (Port 8082)  │  │  (DaemonSet) │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Deployment

### Prerequisites

1. Kubernetes cluster (v1.19+)
2. kubectl configured with cluster access
3. 20GB available storage for metrics retention
4. Network access to container registries

### Quick Start

```bash
# Deploy the complete monitoring stack
./deploy-monitoring.sh

# Or deploy manually
kubectl apply -f k8s-monitoring-stack.yaml

# Check deployment status
kubectl get all -n monitoring
```

### Access Points

After deployment, services are available via NodePort:

| Service | NodePort | Default Credentials | URL |
|---------|----------|-------------------|-----|
| Prometheus | 30090 | None | http://<node-ip>:30090 |
| Grafana | 30300 | admin/catalytic-admin | http://<node-ip>:30300 |
| AlertManager | 30093 | None | http://<node-ip>:30093 |

### Local Access (Port Forwarding)

For secure local access without exposing services:

```bash
# Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090

# Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000

# AlertManager
kubectl port-forward -n monitoring svc/alertmanager 9093:9093
```

## Metrics Collection

### System Metrics

The stack automatically collects:

- **Node Metrics**: CPU, memory, disk, network (via Node Exporter)
- **Pod Metrics**: Resource usage, restarts, status
- **Container Metrics**: CPU, memory, network I/O
- **Kubernetes Metrics**: Deployments, services, ingresses

### Application Metrics

#### Webhook System Metrics (Port 9090)
- `webhook_active_count`: Number of active webhooks
- `webhook_deliveries_total`: Total webhook deliveries
- `webhook_deliveries_successful_total`: Successful deliveries
- `webhook_deliveries_failed_total`: Failed deliveries
- `webhook_delivery_duration_seconds`: Delivery response times
- `webhook_queue_size`: Current queue size

#### Catalytic Computing Metrics (Port 8082)
- `catalytic_memory_efficiency_ratio`: Memory efficiency vs traditional
- `lattice_operations_total`: Total lattice operations
- `xor_transform_duration_ms`: XOR operation performance
- `path_finding_duration_ms`: Path finding performance
- `cache_hits_total` / `cache_misses_total`: Cache performance

### Custom Metrics

To add custom metrics to your application:

```python
# Python example using prometheus_client
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
request_count = Counter('app_requests_total', 'Total requests')
request_duration = Histogram('app_request_duration_seconds', 'Request duration')
active_users = Gauge('app_active_users', 'Active users')

# Use in code
request_count.inc()
with request_duration.time():
    process_request()
active_users.set(get_user_count())
```

## Grafana Dashboards

### Pre-configured Dashboards

1. **Catalytic Computing Performance**
   - Memory efficiency metrics
   - Lattice operation throughput
   - XOR transform performance
   - Cache hit rates
   - GPU acceleration status

2. **Webhook System Monitoring**
   - Active webhooks count
   - Delivery success rates
   - Event distribution
   - Response time metrics
   - Failed webhook tracking

3. **Kubernetes Cluster Overview**
   - Resource utilization by namespace
   - Pod and node status
   - Network traffic
   - Storage usage

### Importing Dashboards

```bash
# Import via API
curl -X POST http://localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -u admin:catalytic-admin \
  -d @grafana-dashboards.json

# Or import via UI:
# 1. Login to Grafana
# 2. Navigate to Dashboards > Import
# 3. Upload grafana-dashboards.json
```

### Creating Custom Dashboards

1. Login to Grafana
2. Click "+" > "Create Dashboard"
3. Add panels with Prometheus queries
4. Save and share dashboard

Example queries:
```promql
# Memory efficiency over time
rate(catalytic_memory_efficiency_ratio[5m])

# Webhook success rate
rate(webhook_deliveries_successful_total[5m]) / rate(webhook_deliveries_total[5m])

# Pod CPU usage
sum(rate(container_cpu_usage_seconds_total{namespace="catalytic-lattice"}[5m])) by (pod)
```

## Alerting

### Pre-configured Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| HighMemoryUsage | Memory > 80% for 5min | Warning | Scale or optimize |
| PodCrashLooping | Restarts > 0 in 15min | Critical | Check logs, fix issue |
| WebhookDeliveryFailure | Failure rate > 10% | Warning | Check endpoints |
| HighCPUUsage | CPU > 80% for 10min | Warning | Scale horizontally |
| DiskSpaceLow | Disk < 10% free | Critical | Clean up or expand |

### Adding Custom Alerts

Edit the Prometheus ConfigMap:

```yaml
- alert: CustomAlert
  expr: your_metric > threshold
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Alert summary"
    description: "Detailed description"
```

Apply changes:
```bash
kubectl apply -f k8s-monitoring-stack.yaml
kubectl rollout restart deployment/prometheus -n monitoring
```

### Alert Routing

Alerts are routed through AlertManager to various receivers:

1. **Webhook Integration**: Sends to webhook system
2. **Email** (optional): Configure SMTP settings
3. **Slack** (optional): Add Slack webhook
4. **PagerDuty** (optional): For critical alerts

## Maintenance

### Backup Metrics Data

```bash
# Create backup
kubectl exec -n monitoring prometheus-0 -- tar czf /tmp/prometheus-backup.tar.gz /prometheus
kubectl cp monitoring/prometheus-0:/tmp/prometheus-backup.tar.gz ./prometheus-backup.tar.gz

# Restore backup
kubectl cp ./prometheus-backup.tar.gz monitoring/prometheus-0:/tmp/
kubectl exec -n monitoring prometheus-0 -- tar xzf /tmp/prometheus-backup.tar.gz -C /
```

### Update Retention Period

Edit Prometheus deployment:
```yaml
args:
  - '--storage.tsdb.retention.time=30d'  # Change to desired retention
```

### Resource Scaling

```bash
# Scale Prometheus resources
kubectl set resources deployment/prometheus -n monitoring \
  --limits=cpu=2,memory=4Gi \
  --requests=cpu=1,memory=2Gi

# Add Grafana replicas for HA
kubectl scale deployment/grafana -n monitoring --replicas=2
```

### Troubleshooting

#### Prometheus Not Scraping Metrics
```bash
# Check targets
curl http://localhost:9090/api/v1/targets

# Check service discovery
kubectl logs -n monitoring deployment/prometheus | grep discovery
```

#### Grafana Dashboard Not Loading
```bash
# Check datasource
curl -u admin:catalytic-admin \
  http://localhost:3000/api/datasources

# Test connection
curl http://localhost:9090/-/healthy
```

#### High Memory Usage
```bash
# Check cardinality
curl http://localhost:9090/api/v1/label/__name__/values | jq '. | length'

# Analyze top series
curl http://localhost:9090/api/v1/query?query=topk\(10,count_by_series\(\)\)
```

## Performance Optimization

### Metric Collection Optimization

1. **Reduce Scrape Frequency**: Increase interval for non-critical metrics
2. **Drop Unnecessary Labels**: Use relabel_configs to remove high-cardinality labels
3. **Use Recording Rules**: Pre-compute frequently used queries

Example recording rule:
```yaml
groups:
- name: recording_rules
  interval: 30s
  rules:
  - record: instance:node_cpu:rate5m
    expr: rate(node_cpu_seconds_total[5m])
```

### Storage Optimization

1. **Enable Compression**: Already enabled by default
2. **Adjust Block Duration**: For write-heavy workloads
3. **Use Remote Storage**: For long-term retention

```yaml
remote_write:
- url: "https://prometheus-storage.example.com/write"
  remote_timeout: 30s
```

### Query Optimization

1. **Use Time Ranges**: Always specify time ranges in queries
2. **Avoid Regex**: Use exact label matches when possible
3. **Leverage Recording Rules**: For complex, frequently-used queries

## Security

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: monitoring-network-policy
  namespace: monitoring
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
  egress:
  - to:
    - namespaceSelector: {}
```

### RBAC Configuration

The monitoring stack uses least-privilege RBAC:
- Prometheus: Read-only access to metrics endpoints
- Grafana: No cluster access (uses Prometheus as proxy)
- AlertManager: Limited to webhook endpoints

### TLS/SSL Setup

For production, enable TLS:

1. Create certificates
2. Mount as secrets
3. Configure services to use TLS

```yaml
volumes:
- name: tls-certs
  secret:
    secretName: monitoring-tls
```

## Integration with CI/CD

### GitOps Integration

```yaml
# Example ArgoCD Application
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: monitoring-stack
spec:
  source:
    repoURL: https://github.com/your-org/k8s-configs
    path: monitoring
    targetRevision: main
  destination:
    server: https://kubernetes.default.svc
    namespace: monitoring
```

### Deployment Notifications

Configure AlertManager to notify on deployments:

```yaml
receivers:
- name: 'deployment-webhook'
  webhook_configs:
  - url: 'https://your-ci-cd/deployment-webhook'
    send_resolved: true
```

## Conclusion

This monitoring stack provides comprehensive observability for the Catalytic Computing system. Key benefits:

- **Real-time Metrics**: Sub-second metric collection
- **Historical Analysis**: 30-day retention by default
- **Proactive Alerting**: Catch issues before they impact users
- **Visual Insights**: Beautiful dashboards for all metrics
- **Scalable Architecture**: Grows with your deployment

For additional support or custom configurations, refer to:
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [AlertManager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)