# Catalytic Computing - Grafana Monitoring Dashboards

Comprehensive monitoring dashboards for the Catalytic Computing platform, featuring system metrics, business metrics, and automated deployment capabilities.

## 📊 Dashboard Overview

### System Metrics Dashboard
Monitors technical performance and infrastructure health:

- **API Performance**: Response times, throughput, and error rates
- **GPU Utilization**: GPU usage, memory, and temperature monitoring
- **Memory Efficiency**: Tracks 28,571x efficiency improvements
- **Processing Speed**: Monitors 649x speed improvement targets
- **Database Performance**: Connection pools and query performance
- **Docker Container Health**: Container status and resource usage
- **Redis Cache Performance**: Hit rates and memory usage
- **Lattice Operations**: XOR transforms and path finding metrics

### Business Metrics Dashboard
Tracks key business KPIs and SaaS metrics:

- **User Metrics**: Registration, activation, and churn rates
- **Revenue Tracking**: MRR, ARR, and growth rates
- **Subscription Analytics**: Trial conversions and cancellations
- **API Usage**: Usage by plan type and limits
- **Payment Processing**: Success/failure rates
- **Support Analytics**: Ticket volumes and resolution times
- **Geographic Distribution**: User locations and regional performance
- **Customer Analytics**: CLV, CAC, and retention metrics

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Grafana and Prometheus services running
- Python 3.7+ for deployment scripts

### 1. Start Monitoring Stack
```bash
# Start monitoring services with Docker Compose
docker compose --profile monitoring up -d

# Or use the setup script for complete automation
python scripts/setup-monitoring.py
```

### 2. Deploy Dashboards
```bash
# Set your Grafana API key
export GRAFANA_API_KEY="your_api_key_here"

# Deploy dashboards automatically
./scripts/deploy-dashboards.sh

# Or on Windows
scripts\deploy-dashboards.bat
```

### 3. Access Dashboards
- **Grafana**: http://localhost:3000
- **Prometheus**: http://localhost:9090

Default Grafana credentials: `admin/admin`

## 📁 Directory Structure

```
monitoring/
├── grafana/
│   ├── dashboards/                    # Dashboard JSON configurations
│   │   ├── system-metrics-dashboard.json
│   │   └── business-metrics-dashboard.json
│   └── provisioning/                  # Grafana provisioning configs
│       ├── dashboards/
│       │   └── dashboard-provisioning.yml
│       └── datasources/
│           └── datasources.yml
├── prometheus/
│   ├── prometheus.yml                 # Prometheus configuration
│   └── alerts/
│       └── catalytic-computing.yml    # Alert rules
└── README.md                          # This file
```

## 🛠 Deployment Scripts

### Automated Setup
- `scripts/setup-monitoring.py`: Complete monitoring stack setup
- `scripts/deploy-grafana-dashboards.py`: Dashboard deployment with validation
- `scripts/validate-dashboards.py`: Dashboard configuration validation

### Platform Scripts
- `scripts/deploy-dashboards.sh`: Linux/macOS deployment
- `scripts/deploy-dashboards.bat`: Windows deployment

## 📊 Metrics Reference

### System Metrics

| Metric | Description | Target/Alert |
|--------|-------------|--------------|
| `catalytic_memory_efficiency_ratio` | Memory efficiency improvement | Target: 28,571x |
| `catalytic_processing_speed_ratio` | Processing speed improvement | Target: 649x |
| `http_request_duration_seconds` | API response times | Alert: >1s (95th percentile) |
| `lattice_operations_total` | Lattice operations per second | Monitor trends |
| `db_connections_active` | Active database connections | Alert: >80% of pool |
| `redis_keyspace_hits_total` | Cache hit rate | Alert: <80% |
| `nvidia_gpu_utilization_gpu` | GPU utilization percentage | Alert: >90% |

### Business Metrics

| Metric | Description | Target/Alert |
|--------|-------------|--------------|
| `current_mrr` | Monthly Recurring Revenue | Growth target: >15% |
| `customer_churn_total` | Customer churn count | Alert: >10% monthly |
| `trial_conversions_total` | Trial to paid conversions | Target: >20% |
| `active_users_by_plan` | Users by subscription plan | Monitor distribution |
| `stripe_payments_successful_total` | Payment success rate | Alert: <98% |
| `customer_lifetime_value` | Average customer LTV | Target: >$1000 |
| `customer_acquisition_cost` | Average customer CAC | Target: <$400 |

## 🔧 Configuration

### Template Variables
Both dashboards include template variables for filtering:
- `environment`: Filter by deployment environment
- `instance`: Filter by specific instances
- `plan_type`: Filter by subscription plan (business dashboard)
- `time_range`: Quick time range selection

### Annotations
- **Deployments**: Marked automatically from Kubernetes
- **Alerts**: Shows firing alerts from Prometheus
- **Product Releases**: Tracks version deployments
- **Marketing Campaigns**: Marks campaign starts

### Refresh Settings
- **System Metrics**: 30-second refresh for real-time monitoring
- **Business Metrics**: 5-minute refresh for trending analysis

## 🚨 Alert Rules

### Critical Alerts
- High API response time (>1s for 5 minutes)
- High error rate (>0.1 req/sec for 2 minutes)
- Database connection pool exhausted (>10 waiting for 2 minutes)

### Warning Alerts
- Memory efficiency below target (<20,000 for 10 minutes)
- Processing speed below target (<500 for 10 minutes)
- Low cache hit rate (<80% for 5 minutes)

## 📈 Performance Targets

### System Performance
- **API Response Time**: <500ms (95th percentile)
- **Memory Efficiency**: 28,571x improvement over traditional methods
- **Processing Speed**: 649x improvement over standard algorithms
- **Cache Hit Rate**: >90%
- **Database Query Time**: <100ms (95th percentile)

### Business Metrics
- **Monthly Growth Rate**: >15%
- **Customer Churn**: <5% monthly
- **Trial Conversion**: >20%
- **Payment Success Rate**: >98%
- **CLV:CAC Ratio**: >5:1

## 🔍 Troubleshooting

### Dashboard Issues
```bash
# Validate dashboard configurations
python scripts/validate-dashboards.py

# Check Grafana logs
docker logs catalytic-grafana

# Test Prometheus connectivity
curl http://localhost:9090/-/healthy
```

### Missing Metrics
1. Verify Prometheus is scraping targets: http://localhost:9090/targets
2. Check service `/metrics` endpoints are accessible
3. Validate metric names in Prometheus: http://localhost:9090/graph

### Deployment Issues
```bash
# Check Docker services status
docker compose ps

# Restart monitoring stack
docker compose --profile monitoring restart

# View detailed logs
docker compose --profile monitoring logs -f
```

## 🔄 Updates and Maintenance

### Dashboard Updates
1. Modify JSON files in `monitoring/grafana/dashboards/`
2. Validate changes: `python scripts/validate-dashboards.py`
3. Deploy updates: `./scripts/deploy-dashboards.sh`

### Adding New Metrics
1. Expose metrics from your application (Prometheus format)
2. Add scrape configuration to `prometheus.yml`
3. Create panels in dashboards using new metrics
4. Test and validate before deployment

### Backup and Recovery
```bash
# Backup current dashboards
curl -H "Authorization: Bearer $GRAFANA_API_KEY" \
     http://localhost:3000/api/search?type=dash-db > dashboard-backup.json

# Export specific dashboard
curl -H "Authorization: Bearer $GRAFANA_API_KEY" \
     http://localhost:3000/api/dashboards/uid/DASHBOARD_UID > dashboard.json
```

## 📞 Support

For issues related to:
- **Dashboard Configuration**: Check validation script output
- **Metric Collection**: Verify Prometheus scraping configuration
- **Performance Issues**: Review alert rules and thresholds
- **Business Metrics**: Validate data source connections

## 🎯 Roadmap

### Planned Enhancements
- [ ] Machine Learning anomaly detection
- [ ] Automated scaling recommendations
- [ ] Advanced forecasting models
- [ ] Custom alerting channels
- [ ] Mobile-responsive dashboard views
- [ ] Real-time collaboration features