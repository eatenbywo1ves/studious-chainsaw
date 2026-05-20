# Kubernetes Deployment Guide

Complete Kubernetes deployment manifests for ML-SecTest Framework.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Manifests Overview](#manifests-overview)
- [Deployment Steps](#deployment-steps)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Production Checklist](#production-checklist)

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured
- Container registry access
- Ingress controller (NGINX recommended)
- cert-manager (optional, for automatic TLS)
- Metrics server (for HPA)

## Quick Start

```bash
# 1. Build and push Docker image
docker build -t your-registry/ml-sectest-framework:1.0.0 .
docker push your-registry/ml-sectest-framework:1.0.0

# 2. Update image in deployment.yaml
sed -i 's|ml-sectest-framework:1.0.0|your-registry/ml-sectest-framework:1.0.0|' k8s/deployment.yaml

# 3. Deploy all manifests
kubectl apply -f k8s/

# 4. Verify deployment
kubectl get all -n ml-sectest
kubectl get ingress -n ml-sectest
```

## Manifests Overview

### Core Resources

1. **namespace.yaml** - Isolated namespace for the application
2. **configmap.yaml** - Application configuration (non-sensitive)
3. **secret.yaml** - Sensitive configuration (SECRET_KEY, API keys)
4. **pvc.yaml** - Persistent storage for SQLite database
5. **deployment.yaml** - Main application deployment (3 replicas)
6. **service.yaml** - ClusterIP service for internal access
7. **ingress.yaml** - External access with TLS
8. **hpa.yaml** - Horizontal Pod Autoscaler (3-10 replicas)

### Resource Requests/Limits

**Per Pod:**
- Requests: 512Mi memory, 500m CPU
- Limits: 2Gi memory, 2000m CPU

**Cluster Requirements (minimum):**
- 3 pods × 512Mi = 1.5Gi memory
- 3 pods × 500m = 1.5 CPU cores

## Deployment Steps

### 1. Create Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 2. Configure Secrets

**IMPORTANT:** Update the SECRET_KEY before deploying!

```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Edit secret.yaml and replace SECRET_KEY
kubectl apply -f k8s/secret.yaml
```

### 3. Deploy Configuration

```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
```

### 4. Deploy Application

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
```

### 5. Configure Ingress

Update `ingress.yaml` with your domain:

```yaml
spec:
  tls:
  - hosts:
    - ml-sectest.yourdomain.com  # Your domain here
    secretName: ml-sectest-tls
  
  rules:
  - host: ml-sectest.yourdomain.com  # Your domain here
```

```bash
kubectl apply -f k8s/ingress.yaml
```

### 6. Verify Deployment

```bash
# Check all resources
kubectl get all -n ml-sectest

# Check pod status
kubectl get pods -n ml-sectest -w

# Check logs
kubectl logs -n ml-sectest -l app=ml-sectest-framework --tail=100

# Check ingress
kubectl get ingress -n ml-sectest
```

## Configuration

### Environment Variables

All configuration is in **configmap.yaml**. Key settings:

```yaml
# API Configuration
API_PORT: "8081"
API_WORKERS: "4"

# CORS (update for your domains)
CORS_ALLOWED_ORIGINS: "https://app.example.com"

# Rate Limiting
RATE_LIMIT_REQUESTS: "100"
RATE_LIMIT_WINDOW: "minute"

# Database
DATABASE_TYPE: "sqlite"
SQLITE_DB_PATH: "/data/ml_sectest.db"
```

### Scaling Configuration

Edit **deployment.yaml** for manual scaling:

```yaml
spec:
  replicas: 5  # Change this number
```

Or use kubectl:

```bash
kubectl scale deployment ml-sectest-api -n ml-sectest --replicas=5
```

### Autoscaling (HPA)

Edit **hpa.yaml** to adjust:

```yaml
spec:
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        averageUtilization: 70  # Trigger at 70% CPU
```

## Monitoring

### Health Checks

```bash
# API health endpoint
kubectl port-forward -n ml-sectest svc/ml-sectest-api 8081:80
curl http://localhost:8081/health

# Prometheus metrics
curl http://localhost:8081/metrics
```

### Pod Status

```bash
# Watch pod status
kubectl get pods -n ml-sectest -w

# Describe pod for events
kubectl describe pod -n ml-sectest <pod-name>

# View logs
kubectl logs -n ml-sectest <pod-name> -f

# View logs from all pods
kubectl logs -n ml-sectest -l app=ml-sectest-framework --tail=100 -f
```

### HPA Status

```bash
# Check autoscaler status
kubectl get hpa -n ml-sectest

# Detailed HPA info
kubectl describe hpa ml-sectest-api-hpa -n ml-sectest
```

### Prometheus Integration

The deployment includes Prometheus annotations:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
  prometheus.io/path: "/metrics"
```

Add ServiceMonitor for Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ml-sectest-metrics
  namespace: ml-sectest
spec:
  selector:
    matchLabels:
      app: ml-sectest-framework
  endpoints:
  - port: metrics
    interval: 30s
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod events
kubectl describe pod -n ml-sectest <pod-name>

# Check logs
kubectl logs -n ml-sectest <pod-name>

# Common issues:
# 1. Image pull errors - check image name and registry access
# 2. ConfigMap/Secret not found - ensure they're created first
# 3. PVC pending - check storage class availability
```

### Database Issues

```bash
# Check PVC status
kubectl get pvc -n ml-sectest

# Check if volume is mounted
kubectl describe pod -n ml-sectest <pod-name> | grep -A 5 Mounts

# Access pod to check database
kubectl exec -it -n ml-sectest <pod-name> -- /bin/bash
ls -la /data/
```

### Ingress Not Working

```bash
# Check ingress status
kubectl get ingress -n ml-sectest
kubectl describe ingress ml-sectest-ingress -n ml-sectest

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx

# Common issues:
# 1. DNS not pointing to ingress IP
# 2. TLS certificate not ready
# 3. Ingress controller not installed
```

### Health Check Failures

```bash
# Port forward and test manually
kubectl port-forward -n ml-sectest svc/ml-sectest-api 8081:80
curl http://localhost:8081/health

# Check service endpoints
kubectl get endpoints -n ml-sectest

# Check pod readiness
kubectl get pods -n ml-sectest -o wide
```

## Production Checklist

Before deploying to production:

### Security

- [ ] Update SECRET_KEY in secret.yaml (use random 32+ char string)
- [ ] Configure API_KEYS if using API key authentication
- [ ] Update CORS_ALLOWED_ORIGINS with production domains
- [ ] Enable TLS in ingress with valid certificates
- [ ] Review and adjust resource limits
- [ ] Enable network policies (optional)
- [ ] Review pod security context

### Configuration

- [ ] Set ENVIRONMENT=production in configmap
- [ ] Set DEBUG=false in configmap
- [ ] Configure proper logging (LOG_LEVEL=INFO or WARNING)
- [ ] Update API_WORKERS based on cluster size
- [ ] Adjust RATE_LIMIT settings for production traffic
- [ ] Configure persistent storage class
- [ ] Set up backup strategy for database

### Monitoring

- [ ] Configure Prometheus scraping
- [ ] Set up alerting rules
- [ ] Configure log aggregation (ELK/Loki)
- [ ] Test health checks
- [ ] Monitor resource usage
- [ ] Configure uptime monitoring

### High Availability

- [ ] Verify min 3 replicas in deployment
- [ ] Configure pod disruption budget
- [ ] Test HPA behavior under load
- [ ] Configure anti-affinity rules (optional)
- [ ] Set up multi-zone deployment (optional)

### Disaster Recovery

- [ ] Document rollback procedure
- [ ] Set up database backups
- [ ] Test restore procedure
- [ ] Configure retention policies
- [ ] Document recovery time objectives

## Cloud-Specific Notes

### Google Kubernetes Engine (GKE)

```yaml
# In ingress.yaml, use:
kubernetes.io/ingress.class: "gce"
kubernetes.io/ingress.global-static-ip-name: "ml-sectest-ip"

# In pvc.yaml:
storageClassName: standard
```

### Amazon EKS

```yaml
# In ingress.yaml, use ALB:
kubernetes.io/ingress.class: "alb"
alb.ingress.kubernetes.io/scheme: "internet-facing"
alb.ingress.kubernetes.io/target-type: "ip"

# In pvc.yaml:
storageClassName: gp2
```

### Azure AKS

```yaml
# In ingress.yaml:
kubernetes.io/ingress.class: "azure/application-gateway"

# In pvc.yaml:
storageClassName: default
```

## Useful Commands

```bash
# Restart deployment
kubectl rollout restart deployment ml-sectest-api -n ml-sectest

# View rollout status
kubectl rollout status deployment ml-sectest-api -n ml-sectest

# Rollback deployment
kubectl rollout undo deployment ml-sectest-api -n ml-sectest

# Scale manually
kubectl scale deployment ml-sectest-api -n ml-sectest --replicas=5

# Update image
kubectl set image deployment/ml-sectest-api -n ml-sectest \
  ml-sectest-api=your-registry/ml-sectest-framework:1.0.1

# Port forward for testing
kubectl port-forward -n ml-sectest svc/ml-sectest-api 8081:80

# Execute command in pod
kubectl exec -it -n ml-sectest <pod-name> -- /bin/bash

# View resource usage
kubectl top pods -n ml-sectest
kubectl top nodes
```

## Support

For issues or questions:
- Check logs: `kubectl logs -n ml-sectest -l app=ml-sectest-framework`
- Review events: `kubectl get events -n ml-sectest --sort-by='.lastTimestamp'`
- Check resource usage: `kubectl top pods -n ml-sectest`

---

**Last Updated:** 2025-10-21  
**Version:** 1.0.0  
**Kubernetes Version:** 1.24+
