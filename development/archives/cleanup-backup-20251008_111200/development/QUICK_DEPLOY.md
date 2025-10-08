# Quick Production Deployment Reference

## 🚀 One-Command Deployment

```bash
# Complete deployment in one script (coming soon)
./scripts/deploy-production.sh
```

---

## 📋 Manual Deployment Steps

### 1. Prerequisites Check ✓

```bash
kubectl version
kubectl cluster-info
helm version
```

### 2. Create Namespace

```bash
kubectl create namespace catalytic-saas
```

### 3. Create Secrets

```bash
# Database
kubectl create secret generic database-credentials \
  --from-literal=url="postgresql://user:pass@host:5432/catalytic_saas" \
  -n catalytic-saas

# JWT
kubectl create secret generic jwt-secret \
  --from-literal=secret="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
  -n catalytic-saas

# Stripe
kubectl create secret generic stripe-secrets \
  --from-literal=api-key="sk_live_..." \
  --from-literal=webhook-secret="whsec_..." \
  -n catalytic-saas
```

### 4. Deploy Application

```bash
cd C:/Users/Corbin/development/kubernetes

kubectl apply -f serviceaccount.yaml
kubectl apply -f configmap.yaml
kubectl apply -f cluster-issuer.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml
```

### 5. Wait for Deployment

```bash
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas --timeout=5m
```

### 6. Run Smoke Tests

```bash
export PRODUCTION_URL=https://api.your-domain.com
cd ../tests/smoke
./smoke_test_runner.sh
```

---

## 🔄 Quick Rollback

```bash
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas
```

---

## 📊 Quick Status Check

```bash
# Pods
kubectl get pods -n catalytic-saas

# Services
kubectl get svc -n catalytic-saas

# Ingress
kubectl get ingress -n catalytic-saas

# Health
curl https://api.your-domain.com/health
```

---

## 📚 Documentation Quick Links

- **Full Deployment Guide**: `docs/deployment/DEPLOYMENT_GUIDE.md`
- **Readiness Checklist**: `docs/deployment/PRODUCTION_READINESS_CHECKLIST.md`
- **Rollback Procedures**: `docs/deployment/ROLLBACK_PROCEDURES.md`
- **Disaster Recovery**: `docs/deployment/DISASTER_RECOVERY.md`
- **Environment Variables**: `docs/deployment/ENVIRONMENT_VARIABLES.md`
- **Database Migrations**: `docs/deployment/DATABASE_MIGRATIONS.md`
- **Kubernetes Guide**: `kubernetes/README.md`
- **Smoke Tests Guide**: `tests/smoke/README.md`
- **Complete Summary**: `C:/Users/Corbin/SYSTEMATIC_EXECUTION_COMPLETE.md`

---

## 🆘 Emergency Contacts

- **DevOps**: oncall-devops@example.com
- **Engineering**: oncall-eng@example.com
- **Security**: security@example.com

---

**Status**: ✅ PRODUCTION READY
**Last Updated**: 2025-10-06
