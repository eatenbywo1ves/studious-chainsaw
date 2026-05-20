# Quick Start Guide - Kubernetes Deployment

## 🚀 Deploy in 5 Minutes

### Prerequisites Check
```bash
# Verify tools
kubectl version --client
docker version
helm version

# Check cluster access
kubectl cluster-info
kubectl get nodes
```

### Step 1: Create Secrets (REQUIRED)
```bash
# Staging secrets
kubectl create namespace catalytic-staging

kubectl create secret generic postgres-credentials \
  --from-literal=username=catalytic_staging \
  --from-literal=password=$(openssl rand -base64 32) \
  -n catalytic-staging

kubectl create secret generic redis-credentials \
  --from-literal=password=$(openssl rand -base64 32) \
  -n catalytic-staging

kubectl create secret generic jwt-secrets \
  --from-literal=jwt-secret=$(openssl rand -hex 64) \
  -n catalytic-staging

kubectl create secret generic api-keys \
  --from-literal=catalytic-api-key=$(openssl rand -hex 32) \
  --from-literal=webhook-signing-secret=$(openssl rand -hex 32) \
  -n catalytic-staging
```

### Step 2: Update Configuration
```bash
# Update image registry (REQUIRED)
cd k8s/
sed -i 's|your-registry/|<YOUR-REGISTRY>/|g' *.yaml

# Update domains in 08-ingress.yaml
# - staging.catalytic.example.com → your-staging-domain.com
# - api.catalytic.example.com → your-api-domain.com
```

### Step 3: Deploy
```bash
# Automated deployment
./deploy.sh staging

# OR manual step-by-step
kubectl apply -f 00-namespace.yaml
kubectl apply -f 01-configmaps.yaml
kubectl apply -f 03-postgres.yaml -n catalytic-staging
kubectl apply -f 04-redis.yaml -n catalytic-staging
kubectl wait --for=condition=ready pod -l app=postgres -n catalytic-staging --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n catalytic-staging --timeout=300s
kubectl apply -f 05-catalytic-api.yaml -n catalytic-staging
kubectl apply -f 06-webhook-system.yaml -n catalytic-staging
kubectl apply -f 07-saas-api.yaml -n catalytic-staging
kubectl apply -f 08-ingress.yaml -n catalytic-staging
kubectl apply -f 09-hpa.yaml -n catalytic-staging
kubectl apply -f 10-network-policies.yaml -n catalytic-staging
```

### Step 4: Verify
```bash
# Check all pods are running
kubectl get pods -n catalytic-staging

# Test health endpoint
kubectl port-forward svc/saas-api 8000:80 -n catalytic-staging &
curl http://localhost:8000/health

# Check logs
kubectl logs -f -l app=saas-api -n catalytic-staging

# View all resources
kubectl get all -n catalytic-staging
```

## 📊 Monitoring Commands

```bash
# Watch HPA auto-scaling
kubectl get hpa -n catalytic-staging --watch

# Monitor pod resources
kubectl top pods -n catalytic-staging

# Check ingress
kubectl get ingress -n catalytic-staging

# Describe problematic pod
kubectl describe pod <pod-name> -n catalytic-staging
```

## 🐛 Quick Troubleshooting

**Pods not starting?**
```bash
kubectl describe pod <pod-name> -n catalytic-staging
kubectl logs <pod-name> -n catalytic-staging
```

**Database connection errors?**
```bash
# Verify postgres is running
kubectl get pods -l app=postgres -n catalytic-staging

# Test connection
kubectl exec -it <saas-api-pod> -n catalytic-staging -- \
  psql postgresql://catalytic_staging:<password>@postgres:5432/catalytic_saas
```

**Ingress not working?**
```bash
# Check ingress controller
kubectl get pods -n ingress-nginx

# Get ingress IP/hostname
kubectl get ingress -n catalytic-staging

# Test without ingress
kubectl port-forward svc/saas-api 8000:80 -n catalytic-staging
```

## 🔄 Common Operations

### Update Image
```bash
kubectl set image deployment/saas-api \
  saas-api=your-registry/catalytic-saas:v1.1 \
  -n catalytic-staging
```

### Scale Manually
```bash
kubectl scale deployment/saas-api --replicas=5 -n catalytic-staging
```

### Restart Deployment
```bash
kubectl rollout restart deployment/saas-api -n catalytic-staging
```

### Rollback
```bash
kubectl rollout undo deployment/saas-api -n catalytic-staging
```

### View Logs
```bash
# All pods for an app
kubectl logs -f -l app=saas-api -n catalytic-staging

# Specific pod
kubectl logs -f <pod-name> -n catalytic-staging

# Previous container (if crashed)
kubectl logs <pod-name> -n catalytic-staging --previous
```

### Execute Commands
```bash
# Redis CLI
kubectl exec -it redis-0 -n catalytic-staging -- redis-cli

# PostgreSQL
kubectl exec -it postgres-0 -n catalytic-staging -- \
  psql -U catalytic_staging catalytic_saas

# Shell in pod
kubectl exec -it <pod-name> -n catalytic-staging -- /bin/sh
```

## 🔐 Security Checklist

- [ ] Strong secrets generated (min 32 chars)
- [ ] Secrets stored in external secret manager (not in Git)
- [ ] TLS certificates configured
- [ ] Network policies applied
- [ ] RBAC configured
- [ ] Image registry secured with credentials
- [ ] No sensitive data in ConfigMaps
- [ ] Pod Security Standards enforced

## 📈 Performance Checklist

- [ ] Resource requests/limits set
- [ ] HPA configured
- [ ] Persistent volumes use fast storage (SSD)
- [ ] Database connection pooling enabled
- [ ] Redis maxmemory policy set
- [ ] Monitoring and alerting configured
- [ ] Log aggregation setup

## 🎯 Production Checklist

Before deploying to production:

- [ ] All staging tests passed
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Backup strategy implemented
- [ ] Monitoring dashboards created
- [ ] Alerting rules configured
- [ ] Runbook documentation complete
- [ ] Team trained on incident response
- [ ] Rollback procedure tested
- [ ] Circuit breaker thresholds tuned

## 🆘 Emergency Contacts

- **DevOps Team**: devops@example.com
- **On-Call**: +1-555-ON-CALL
- **Incident Manager**: incidents@example.com

## 📚 More Information

- Full documentation: [README.md](README.md)
- Architecture diagrams: [docs/architecture.md](../docs/architecture.md)
- API documentation: [docs/api.md](../docs/api.md)
- Runbooks: [docs/runbooks/](../docs/runbooks/)
