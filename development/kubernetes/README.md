# Kubernetes Deployment Guide

## Overview

This directory contains Kubernetes manifests for deploying the Catalytic Computing SaaS platform to a Kubernetes cluster.

---

## Prerequisites

1. **Kubernetes Cluster** (v1.19+)
   - GKE, EKS, AKS, or self-managed
   - Minimum 3 nodes
   - Each node: 4 vCPUs, 8GB RAM

2. **kubectl** configured for your cluster
   ```bash
   kubectl version
   kubectl cluster-info
   ```

3. **NGINX Ingress Controller** (or similar)
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml
   ```

4. **cert-manager** (for SSL certificates)
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
   ```

5. **Metrics Server** (for HPA)
   ```bash
   kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
   ```

---

## Quick Start

### Step 1: Create Namespace

```bash
kubectl create namespace catalytic-saas
kubectl label namespace catalytic-saas environment=production
```

### Step 2: Create Secrets

⚠️ **IMPORTANT**: Never commit secrets to git!

```bash
# Copy example and edit with real values
cp secrets.yaml.example secrets.yaml
# Edit secrets.yaml (use a secure editor, not a shared one)
nano secrets.yaml

# Apply secrets
kubectl apply -f secrets.yaml

# Delete file after applying
rm secrets.yaml
```

**OR** create secrets from command line (recommended):

```bash
# Database credentials
kubectl create secret generic database-credentials \
  --from-literal=url="postgresql://user:pass@host:5432/catalytic_saas" \
  -n catalytic-saas

# Redis credentials
kubectl create secret generic redis-credentials \
  --from-literal=url="redis://:pass@redis-host:6379/0" \
  -n catalytic-saas

# JWT secret
kubectl create secret generic jwt-secret \
  --from-literal=secret="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
  -n catalytic-saas

# Stripe secrets
kubectl create secret generic stripe-secrets \
  --from-literal=api-key="sk_live_..." \
  --from-literal=webhook-secret="whsec_..." \
  -n catalytic-saas
```

### Step 3: Update ConfigMap

Edit `configmap.yaml` and update:
- `ALLOWED_ORIGINS`: Your production domains
- Other environment-specific settings

```bash
kubectl apply -f configmap.yaml
```

### Step 4: Update Ingress

Edit `ingress.yaml` and replace:
- `api.your-domain.com` with your actual domain
- Update email in `cluster-issuer.yaml`

```bash
kubectl apply -f cluster-issuer.yaml
kubectl apply -f ingress.yaml
```

### Step 5: Deploy Application

```bash
# Create service account and RBAC
kubectl apply -f serviceaccount.yaml

# Deploy application
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Deploy horizontal pod autoscaler
kubectl apply -f hpa.yaml

# Verify deployment
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas
kubectl get pods -n catalytic-saas
```

### Step 6: Verify Deployment

```bash
# Check pods are running
kubectl get pods -n catalytic-saas

# Check services
kubectl get svc -n catalytic-saas

# Check ingress
kubectl get ingress -n catalytic-saas

# Check certificate (wait 1-2 minutes for issuance)
kubectl get certificate -n catalytic-saas
kubectl describe certificate catalytic-tls -n catalytic-saas

# Test health endpoint
curl https://api.your-domain.com/health
```

---

## Manifest Files

### Core Manifests

| File | Description |
|------|-------------|
| `deployment.yaml` | Main application deployment |
| `service.yaml` | Service and metrics endpoints |
| `ingress.yaml` | Ingress with TLS and security headers |
| `configmap.yaml` | Non-sensitive configuration |
| `secrets.yaml.example` | Template for secrets (DO NOT commit actual secrets) |

### Supporting Manifests

| File | Description |
|------|-------------|
| `hpa.yaml` | Horizontal Pod Autoscaler (3-20 replicas) |
| `cluster-issuer.yaml` | Let's Encrypt SSL certificate issuer |
| `serviceaccount.yaml` | Service account and RBAC rules |

### Optional Manifests

| File | Description |
|------|-------------|
| `networkpolicy.yaml` | Network policies (create if needed) |
| `poddisruptionbudget.yaml` | PDB for availability (create if needed) |

---

## Configuration

### Environment Variables

Configure via `configmap.yaml`:
- `ENVIRONMENT`: `production`
- `LOG_LEVEL`: `INFO`
- `ALLOWED_ORIGINS`: Your domains
- `RATE_LIMIT_PER_MINUTE`: `100`
- Other app settings

Configure via secrets (create separately):
- `DATABASE_URL`: Database connection string
- `REDIS_URL`: Redis connection string (optional)
- `JWT_SECRET`: JWT signing secret
- `STRIPE_API_KEY`: Stripe API key
- `STRIPE_WEBHOOK_SECRET`: Stripe webhook secret

### Resource Limits

Default per pod:
- **Requests**: 500m CPU, 1Gi memory
- **Limits**: 1000m CPU, 2Gi memory

Adjust in `deployment.yaml` based on your needs.

### Scaling

**Horizontal Pod Autoscaler** (HPA):
- Min replicas: 3
- Max replicas: 20
- CPU target: 70%
- Memory target: 80%

**Manual scaling**:
```bash
# Scale to specific number
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=5

# Disable autoscaling (delete HPA)
kubectl delete hpa catalytic-saas-hpa -n catalytic-saas
```

---

## Deployment Procedures

### Standard Deployment

```bash
# 1. Build and push new image
docker build -t your-registry.io/catalytic-saas-api:v1.1.0 .
docker push your-registry.io/catalytic-saas-api:v1.1.0

# 2. Update deployment image
kubectl set image deployment/catalytic-saas-api \
  catalytic-saas-api=your-registry.io/catalytic-saas-api:v1.1.0 \
  -n catalytic-saas

# 3. Monitor rollout
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas

# 4. Verify
kubectl get pods -n catalytic-saas
curl https://api.your-domain.com/health
```

### Blue-Green Deployment

```bash
# 1. Deploy new version alongside old (label: version=v1.1.0)
kubectl apply -f deployment-v1.1.0.yaml

# 2. Test new version
kubectl port-forward deployment/catalytic-saas-api-v1.1.0 8000:8000 -n catalytic-saas
curl http://localhost:8000/health

# 3. Switch traffic (update service selector)
kubectl patch service catalytic-saas-api -n catalytic-saas \
  -p '{"spec":{"selector":{"version":"v1.1.0"}}}'

# 4. Delete old version
kubectl delete deployment catalytic-saas-api-v1.0.0 -n catalytic-saas
```

### Canary Deployment

```bash
# 1. Deploy canary (10% traffic)
kubectl apply -f deployment-canary.yaml

# 2. Update ingress for traffic split
# Use ingress controller annotations for weighted routing

# 3. Monitor canary metrics
kubectl logs -f deployment/catalytic-saas-api-canary -n catalytic-saas

# 4. Roll out to 100% if successful
kubectl scale deployment/catalytic-saas-api-canary --replicas=3
kubectl scale deployment/catalytic-saas-api --replicas=0
```

---

## Rollback

### Quick Rollback

```bash
# Rollback to previous version
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas

# Rollback to specific revision
kubectl rollout history deployment/catalytic-saas-api -n catalytic-saas
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas --to-revision=3
```

### Emergency Stop

```bash
# Scale to 0 (stop all traffic)
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=0

# Delete ingress (remove from load balancer)
kubectl delete ingress catalytic-ingress -n catalytic-saas
```

---

## Monitoring & Debugging

### View Logs

```bash
# All pods
kubectl logs -f deployment/catalytic-saas-api -n catalytic-saas

# Specific pod
kubectl logs -f <pod-name> -n catalytic-saas

# Previous container (if pod restarted)
kubectl logs <pod-name> -n catalytic-saas --previous
```

### Describe Resources

```bash
# Deployment
kubectl describe deployment catalytic-saas-api -n catalytic-saas

# Pod
kubectl describe pod <pod-name> -n catalytic-saas

# Service
kubectl describe service catalytic-saas-api -n catalytic-saas

# Ingress
kubectl describe ingress catalytic-ingress -n catalytic-saas
```

### Execute Commands in Pod

```bash
# Interactive shell
kubectl exec -it <pod-name> -n catalytic-saas -- /bin/sh

# Run single command
kubectl exec <pod-name> -n catalytic-saas -- python scripts/verify_database.py
```

### Port Forwarding

```bash
# Forward API port
kubectl port-forward deployment/catalytic-saas-api 8000:8000 -n catalytic-saas

# Forward metrics port
kubectl port-forward deployment/catalytic-saas-api 8082:8082 -n catalytic-saas
```

### Resource Usage

```bash
# Pod resource usage
kubectl top pods -n catalytic-saas

# Node resource usage
kubectl top nodes

# HPA status
kubectl get hpa -n catalytic-saas
```

---

## Troubleshooting

### Pods Not Starting

**Issue**: Pods stuck in `Pending` or `CrashLoopBackOff`

**Debug**:
```bash
# Check events
kubectl get events -n catalytic-saas --sort-by=.metadata.creationTimestamp

# Describe pod
kubectl describe pod <pod-name> -n catalytic-saas

# Check logs
kubectl logs <pod-name> -n catalytic-saas
```

**Common causes**:
- Insufficient resources (check node capacity)
- Missing secrets (check secret exists)
- Image pull errors (check image name and registry auth)
- Health check failures (check health endpoint)

### Certificate Not Issuing

**Issue**: Certificate stuck in `Pending` or `False`

**Debug**:
```bash
# Check certificate
kubectl describe certificate catalytic-tls -n catalytic-saas

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Check challenge
kubectl get challenges -n catalytic-saas
kubectl describe challenge <challenge-name> -n catalytic-saas
```

**Common causes**:
- DNS not pointing to ingress IP
- Firewall blocking port 80 (needed for HTTP-01 challenge)
- Rate limit hit (use staging issuer first)

### High Memory Usage / OOMKilled

**Issue**: Pods getting killed due to OOM

**Solution**:
```bash
# Increase memory limits
kubectl set resources deployment/catalytic-saas-api \
  -n catalytic-saas \
  --limits=memory=4Gi \
  --requests=memory=2Gi

# Or edit deployment
kubectl edit deployment catalytic-saas-api -n catalytic-saas
```

### Service Unavailable

**Issue**: 503 errors from ingress

**Debug**:
```bash
# Check pods are ready
kubectl get pods -n catalytic-saas

# Check service endpoints
kubectl get endpoints catalytic-saas-api -n catalytic-saas

# Check ingress
kubectl describe ingress catalytic-ingress -n catalytic-saas
```

---

## Security Best Practices

1. **Never commit secrets to git**
   - Use `.gitignore` for `secrets.yaml`
   - Create secrets from command line or secret manager

2. **Use RBAC**
   - Limit pod permissions with service accounts
   - Use network policies to restrict traffic

3. **Enable Pod Security**
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 1000
     allowPrivilegeEscalation: false
   ```

4. **Rotate Secrets Regularly**
   ```bash
   # Create new secret
   kubectl create secret generic jwt-secret-new \
     --from-literal=secret="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
     -n catalytic-saas

   # Update deployment to use new secret
   # Then delete old secret
   kubectl delete secret jwt-secret -n catalytic-saas
   ```

5. **Use Network Policies**
   - Restrict ingress to only what's needed
   - Restrict egress to known services

---

## Production Checklist

Before deploying to production:

- [ ] Secrets created and verified
- [ ] ConfigMap updated with production values
- [ ] Ingress configured with production domain
- [ ] SSL certificate issued and valid
- [ ] Resource limits appropriate for workload
- [ ] HPA configured and tested
- [ ] Health checks passing
- [ ] Monitoring and alerting configured
- [ ] Backup strategy in place
- [ ] Rollback plan documented and tested
- [ ] Team trained on deployment procedures

---

## Additional Resources

- **Kubernetes Documentation**: https://kubernetes.io/docs/
- **NGINX Ingress Controller**: https://kubernetes.github.io/ingress-nginx/
- **cert-manager**: https://cert-manager.io/docs/
- **Helm** (for more complex deployments): https://helm.sh/

---

**Maintained By**: DevOps Team
**Last Updated**: 2025-10-06
**Review Frequency**: Quarterly
