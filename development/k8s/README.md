# Catalytic Computing Platform - Kubernetes Deployment

Comprehensive Kubernetes manifests for deploying the Catalytic Computing Platform with high availability, auto-scaling, and security best practices.

## 📋 Architecture Overview

This deployment includes:

- **Catalytic API** - Main API gateway (auto-scaling 2-20 pods)
- **Webhook System** - Event-driven webhook processing (auto-scaling 2-15 pods)
- **SaaS API** - Authentication service with Redis circuit breaker (auto-scaling 2-20 pods)
- **PostgreSQL** - Primary database with persistent storage
- **Redis** - Caching and session storage with persistence
- **Monitoring** - Prometheus metrics exporters for all services
- **Security** - Network policies, RBAC, secrets management, TLS

## 🗂️ File Structure

```
k8s/
├── 00-namespace.yaml              # Namespaces, quotas, and limits
├── 01-configmaps.yaml             # Non-sensitive configuration
├── 02-secrets.yaml                # Secret templates (REPLACE VALUES!)
├── 03-postgres.yaml               # PostgreSQL StatefulSet + PVC
├── 04-redis.yaml                  # Redis StatefulSet + PVC
├── 05-catalytic-api.yaml          # Catalytic API Deployment
├── 06-webhook-system.yaml         # Webhook System Deployment
├── 07-saas-api.yaml               # SaaS API Deployment (Auth)
├── 08-ingress.yaml                # NGINX Ingress with TLS
├── 09-hpa.yaml                    # HorizontalPodAutoscaler + PDB
├── 10-network-policies.yaml       # Pod-level firewall rules
├── auth-service-base.yaml         # Auth service stable deployment
├── auth-service-canary.yaml       # Auth service canary deployment
├── istio-traffic-split.yaml       # Istio progressive rollout
└── monitoring/
    ├── grafana-circuit-breaker-dashboard.json
    └── prometheus-servicemonitor.yaml
```

## 🚀 Quick Start

### Prerequisites

1. **Kubernetes Cluster** (v1.24+)
   - Managed: EKS, GKE, AKS, or similar
   - Self-hosted: kubeadm, k3s, etc.

2. **Required Add-ons**:
   ```bash
   # NGINX Ingress Controller
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml

   # Metrics Server (for HPA)
   kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

   # cert-manager (optional, for automatic TLS)
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
   ```

3. **Tools**:
   ```bash
   kubectl version --client
   helm version
   docker version
   ```

### Step 1: Configure Secrets

**⚠️ CRITICAL**: Replace placeholder values in `02-secrets.yaml` with strong, randomly generated secrets:

```bash
# Generate strong passwords
openssl rand -base64 32  # For database passwords
openssl rand -base64 48  # For production secrets
openssl rand -hex 64     # For JWT secrets

# Generate RSA key pair for JWT (RS256)
ssh-keygen -t rsa -b 4096 -m PEM -f jwt-key
```

Create secrets directly (recommended for production):

```bash
# Staging secrets
kubectl create secret generic postgres-credentials \
  --from-literal=username=catalytic_staging \
  --from-literal=password=$(openssl rand -base64 32) \
  -n catalytic-staging

kubectl create secret generic redis-credentials \
  --from-literal=password=$(openssl rand -base64 32) \
  -n catalytic-staging

kubectl create secret generic jwt-secrets \
  --from-file=jwt-private-key=jwt-key \
  --from-file=jwt-public-key=jwt-key.pub \
  -n catalytic-staging

kubectl create secret generic api-keys \
  --from-literal=catalytic-api-key=$(openssl rand -hex 32) \
  --from-literal=webhook-signing-secret=$(openssl rand -hex 32) \
  -n catalytic-staging

# Production secrets (repeat with different values)
# ...
```

### Step 2: Update ConfigMaps

Edit `01-configmaps.yaml`:

- Update domain names
- Adjust resource limits
- Configure circuit breaker thresholds
- Set appropriate log levels

### Step 3: Update Image References

Replace `your-registry/` with your actual container registry:

```bash
# Example: Using Docker Hub
sed -i 's|your-registry/|docker.io/yourcompany/|g' k8s/*.yaml

# Example: Using AWS ECR
sed -i 's|your-registry/|123456789012.dkr.ecr.us-east-1.amazonaws.com/|g' k8s/*.yaml

# Example: Using Google Container Registry
sed -i 's|your-registry/|gcr.io/your-project/|g' k8s/*.yaml
```

### Step 4: Deploy to Staging

```bash
# Create staging namespace and resources
./deploy.sh staging

# Or manually:
kubectl apply -f 00-namespace.yaml
kubectl apply -f 01-configmaps.yaml
kubectl apply -f 02-secrets.yaml  # If using template
kubectl apply -f 03-postgres.yaml -n catalytic-staging
kubectl apply -f 04-redis.yaml -n catalytic-staging

# Wait for databases to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n catalytic-staging --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n catalytic-staging --timeout=300s

# Deploy applications
kubectl apply -f 05-catalytic-api.yaml -n catalytic-staging
kubectl apply -f 06-webhook-system.yaml -n catalytic-staging
kubectl apply -f 07-saas-api.yaml -n catalytic-staging

# Deploy ingress and scaling
kubectl apply -f 08-ingress.yaml -n catalytic-staging
kubectl apply -f 09-hpa.yaml -n catalytic-staging
kubectl apply -f 10-network-policies.yaml -n catalytic-staging
```

### Step 5: Verify Deployment

```bash
# Check pod status
kubectl get pods -n catalytic-staging -o wide

# Check services
kubectl get svc -n catalytic-staging

# Check ingress
kubectl get ingress -n catalytic-staging

# Check logs
kubectl logs -f -l app=saas-api -n catalytic-staging

# Check HPA status
kubectl get hpa -n catalytic-staging

# Test health endpoints
kubectl port-forward svc/saas-api 8000:80 -n catalytic-staging
curl http://localhost:8000/health
```

## 🔧 Configuration

### Environment-Specific Settings

| Setting | Staging | Production |
|---------|---------|------------|
| Min Replicas | 2 | 3 |
| Max Replicas | 10 | 20 |
| CPU Target | 70% | 65% |
| Memory Target | 80% | 75% |
| Circuit Breaker | fail_open | fail_closed |
| Log Level | DEBUG | INFO |
| Access Token TTL | 30 min | 15 min |

### Scaling Configuration

The HPA scales based on:
- **CPU utilization** (65-70% target)
- **Memory utilization** (75-80% target)
- **Custom metrics** (optional, via Prometheus adapter)

Scale-down is conservative (5-10 minute stabilization) to prevent flapping.

### Circuit Breaker Configuration

Redis circuit breaker protects against Redis outages:

| Parameter | Staging | Production |
|-----------|---------|------------|
| Failure Threshold | 5 | 5 |
| Failure Timeout | 60s | 120s |
| Reset Timeout | 120s | 180s |
| Success Threshold | 3 | 3 |
| Fallback Strategy | fail_open | fail_closed |

## 🔐 Security

### Network Policies

Default deny-all policies with explicit allow rules:

- **PostgreSQL**: Only accessible from saas-api
- **Redis**: Only accessible from application pods
- **Services**: Only accept traffic from ingress controller
- **Metrics**: Only accessible from monitoring namespace
- **DNS**: Allowed for all pods

### Secrets Management

Three options (in order of security):

1. **External Secrets Operator** (Recommended)
   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault

2. **Sealed Secrets**
   - Encrypt secrets in Git
   - Controller decrypts in-cluster

3. **kubectl create secret** (Manual)
   - Create secrets imperatively
   - Never commit to Git

### RBAC

Service accounts with minimal permissions:
- Each service has its own ServiceAccount
- No default service account usage
- Pod security policies enforced

### TLS/SSL

Configure TLS certificates:

1. **cert-manager** (Automated)
   ```yaml
   annotations:
     cert-manager.io/cluster-issuer: "letsencrypt-prod"
   ```

2. **Manual**
   ```bash
   kubectl create secret tls catalytic-tls \
     --cert=path/to/tls.crt \
     --key=path/to/tls.key \
     -n catalytic-production
   ```

## 📊 Monitoring

### Prometheus Metrics

All services expose metrics:

- **Catalytic API**: `:8082/metrics`
- **SaaS API**: `:8001/metrics`
- **Webhook System**: `:9090/metrics`
- **PostgreSQL**: `:9187/metrics` (postgres_exporter)
- **Redis**: `:9121/metrics` (redis_exporter)

### Circuit Breaker Metrics

Monitor circuit breaker state:

```promql
# Circuit breaker state (0=closed, 1=open, 2=half-open)
circuit_breaker_state{service="redis"}

# Failure count
circuit_breaker_failures_total{service="redis"}

# Success count in half-open state
circuit_breaker_successes_total{service="redis"}
```

### Dashboards

Import Grafana dashboards:
- `monitoring/grafana-circuit-breaker-dashboard.json`
- Kubernetes pod metrics
- Application-specific metrics

## 🚢 Deployment Strategies

### Rolling Update (Default)

Standard zero-downtime deployment:
```bash
kubectl set image deployment/saas-api saas-api=your-registry/catalytic-saas:v2.0 -n catalytic-staging
```

### Canary Deployment

Use `auth-service-canary.yaml` for progressive rollout:

1. Deploy canary with new version
2. Configure Istio traffic split (10% → 50% → 100%)
3. Monitor metrics
4. Promote or rollback

```bash
kubectl apply -f auth-service-canary.yaml -n catalytic-production
kubectl apply -f istio-traffic-split.yaml -n catalytic-production
```

### Blue-Green Deployment

Deploy to new namespace, switch ingress:

```bash
# Deploy to blue
kubectl apply -f . -n catalytic-blue

# Switch ingress
kubectl patch ingress catalytic-ingress -n catalytic-production \
  -p '{"spec":{"rules":[{"host":"api.catalytic.example.com","http":{"paths":[{"backend":{"service":{"name":"catalytic-api-blue"}}}]}}]}}'
```

## 🧪 Testing

### Health Checks

```bash
# Liveness (is container alive?)
curl http://api.example.com/health/liveness

# Readiness (can container serve traffic?)
curl http://api.example.com/health/readiness

# Startup (has container finished starting?)
curl http://api.example.com/health/startup
```

### Load Testing

```bash
# Install k6 or hey
brew install k6

# Run load test
k6 run loadtest.js

# Or use hey
hey -n 10000 -c 100 http://api.example.com/api/v1/status
```

### Circuit Breaker Testing

```bash
# Simulate Redis failure
kubectl exec -it redis-0 -n catalytic-staging -- redis-cli shutdown

# Check circuit breaker opens
kubectl logs -f -l app=saas-api -n catalytic-staging | grep "circuit breaker"

# Restart Redis
kubectl rollout restart statefulset/redis -n catalytic-staging

# Watch circuit breaker close
```

## 📈 Performance Tuning

### PostgreSQL

Adjust in `03-postgres.yaml`:
```yaml
shared_buffers: "512MB"  # 25% of RAM
effective_cache_size: "2GB"  # 50-75% of RAM
work_mem: "8MB"  # Increase for complex queries
```

### Redis

Adjust in `04-redis.yaml`:
```yaml
maxmemory: "2gb"
maxmemory-policy: "allkeys-lru"
```

### Application

Tune resource requests/limits:
```yaml
resources:
  requests:
    memory: "512Mi"  # Minimum guaranteed
    cpu: "250m"
  limits:
    memory: "2Gi"  # Maximum allowed
    cpu: "1000m"
```

## 🔄 Backup and Disaster Recovery

### PostgreSQL Backups

Automated backups (if using managed DB):
- Daily full backups
- Point-in-time recovery (PITR)
- Cross-region replication

Manual backup:
```bash
kubectl exec postgres-0 -n catalytic-production -- \
  pg_dump -U catalytic_prod catalytic_saas | \
  gzip > backup-$(date +%Y%m%d).sql.gz
```

### Redis Backups

Redis persistence enabled (AOF + RDB):
- AOF: `appendfsync everysec`
- RDB: `save 900 1 / save 300 10 / save 60 10000`

Manual backup:
```bash
kubectl exec redis-0 -n catalytic-production -- \
  redis-cli --no-auth-warning -a $REDIS_PASSWORD save

kubectl cp catalytic-production/redis-0:/data/dump.rdb ./redis-backup.rdb
```

## 🐛 Troubleshooting

### Common Issues

**Pods not starting:**
```bash
kubectl describe pod <pod-name> -n catalytic-staging
kubectl logs <pod-name> -n catalytic-staging --previous
```

**ImagePullBackOff:**
```bash
# Check image exists and credentials
kubectl get events -n catalytic-staging
kubectl create secret docker-registry regcred \
  --docker-server=<registry> \
  --docker-username=<username> \
  --docker-password=<password>
```

**Database connection failed:**
```bash
# Check postgres is ready
kubectl get pods -l app=postgres -n catalytic-staging

# Test connection
kubectl exec -it saas-api-xxx -n catalytic-staging -- \
  psql postgresql://user:pass@postgres:5432/catalytic_saas
```

**HPA not scaling:**
```bash
# Check metrics-server
kubectl get apiservice v1beta1.metrics.k8s.io -o yaml

# Check HPA status
kubectl describe hpa saas-api-hpa -n catalytic-staging
```

**Network policy blocking traffic:**
```bash
# Temporarily disable to test
kubectl delete networkpolicy --all -n catalytic-staging

# Check policy rules
kubectl describe networkpolicy <policy-name> -n catalytic-staging
```

## 📚 Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
- [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)

## 📝 Maintenance

### Regular Tasks

- **Daily**: Check pod health, review logs
- **Weekly**: Review metrics, adjust HPA if needed
- **Monthly**: Update images, security patches
- **Quarterly**: Disaster recovery drill, performance review

### Upgrades

```bash
# Rolling upgrade
kubectl set image deployment/saas-api \
  saas-api=your-registry/catalytic-saas:v2.0 \
  -n catalytic-production

# Rollback if needed
kubectl rollout undo deployment/saas-api -n catalytic-production

# Check rollout status
kubectl rollout status deployment/saas-api -n catalytic-production
```

## 🤝 Support

For issues or questions:
1. Check logs: `kubectl logs -f <pod-name> -n <namespace>`
2. Review events: `kubectl get events -n <namespace>`
3. Check documentation above
4. Contact DevOps team

---

**Last Updated**: 2025-01-30
**Version**: 1.0.0
**Maintainer**: DevOps Team
