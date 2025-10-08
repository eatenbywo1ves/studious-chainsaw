# Rollback Procedures

## Emergency Rollback Guide

**Purpose**: Quickly restore service when a deployment fails
**Target Time**: < 5 minutes for application rollback, < 15 minutes with database restore

---

## When to Rollback

### Automatic Rollback Triggers

Execute immediate rollback if ANY of these conditions are met:

| Trigger | Threshold | Detection Method |
|---------|-----------|------------------|
| Error Rate Spike | > 5% for 5 minutes | Prometheus alert |
| Response Time Degradation | p95 > 200ms for 10 minutes | Prometheus alert |
| Service Unavailability | Health check fails for 3 consecutive checks | Monitoring |
| Critical Workflow Failure | Registration/Login broken | Smoke tests |
| Database Corruption | Data integrity check fails | Application logs |
| Memory Leak | OOMKilled > 3 pods in 5 minutes | Kubernetes events |
| Security Breach | Unauthorized access detected | Security logs |

### Manual Rollback Criteria

Consider rollback for:
- Smoke test failure rate > 50%
- Customer complaints spike
- Business logic errors discovered
- Performance degradation affecting users
- Unexpected behavior in production

---

## Rollback Levels

### Level 1: Application-Only Rollback (< 5 minutes)

**Use when**:
- Code changes only (no schema changes)
- Configuration errors
- Performance issues
- Minor bugs

**Procedure**:
```bash
# Quick rollback to previous version
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas

# Monitor rollback progress
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas
```

### Level 2: Application + Configuration Rollback (< 10 minutes)

**Use when**:
- Environment variable changes
- ConfigMap/Secret changes
- Feature flag issues

**Procedure**:
```bash
# Restore ConfigMaps
kubectl apply -f backups/configmap-backup-<timestamp>.yaml

# Restore Secrets (if changed)
kubectl apply -f backups/secrets-backup-<timestamp>.yaml

# Rollback application
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas

# Restart pods to pick up config
kubectl rollout restart deployment/catalytic-saas-api -n catalytic-saas
```

### Level 3: Full Rollback with Database Restore (< 15 minutes)

**Use when**:
- Database migration failed
- Data corruption detected
- Schema changes incompatible

**Procedure**: See [Full Rollback Procedure](#full-rollback-procedure) below

---

## Quick Rollback Procedure (Level 1)

### Step 1: Stop Deployment (0-1 minute)

```bash
# If deployment is in progress, cancel it
kubectl rollout pause deployment/catalytic-saas-api -n catalytic-saas

# OR scale to 0 to stop all traffic immediately
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=0
```

### Step 2: Rollback Application (1-3 minutes)

```bash
# Rollback to previous revision
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas

# Check rollback status
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas --timeout=3m

# Verify pods are running
kubectl get pods -n catalytic-saas -l app=catalytic-saas-api
```

### Step 3: Verify Rollback (3-5 minutes)

```bash
# Run smoke tests
export PRODUCTION_URL=https://api.your-domain.com
cd tests/smoke
./smoke_test_runner.sh

# Check health endpoint
curl https://api.your-domain.com/health

# Verify metrics
kubectl port-forward -n catalytic-saas svc/prometheus 9090:9090 &
curl http://localhost:9090/api/v1/query?query=up
```

### Step 4: Resume Traffic (if scaled to 0)

```bash
# Scale back up
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=3

# Monitor pod startup
kubectl get pods -n catalytic-saas -w
```

---

## Full Rollback Procedure (Level 3)

### Step 1: Declare Incident (0-1 minute)

```bash
# Alert team via PagerDuty/Slack
# Sample command:
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "🚨 PRODUCTION ROLLBACK IN PROGRESS 🚨",
    "blocks": [
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "*Production Rollback Initiated*\nReason: <Describe reason>\nExpected Duration: 15 minutes"
        }
      }
    ]
  }'

# Update status page
# curl -X POST https://api.statuspage.io/v1/pages/YOUR_PAGE_ID/incidents ...
```

### Step 2: Stop All Traffic (1-2 minutes)

```bash
# Scale deployment to 0
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=0

# Verify all pods terminated
kubectl get pods -n catalytic-saas -l app=catalytic-saas-api

# Optional: Remove from load balancer
kubectl delete ingress catalytic-ingress -n catalytic-saas
```

### Step 3: Restore Database (2-7 minutes)

**Identify Backup to Restore**:
```bash
# List available backups
./scripts/list-backups.sh production

# Identify last known good backup (before failed deployment)
BACKUP_TIMESTAMP="20251006_120000"  # Example: before deployment
```

**Restore from Backup**:
```bash
# PostgreSQL restore
export DATABASE_URL="postgresql://user:password@db-host:5432/catalytic_saas"

# Drop current database (CAUTION!)
psql -c "DROP DATABASE catalytic_saas;"
psql -c "CREATE DATABASE catalytic_saas;"

# Restore from backup
pg_restore -d catalytic_saas backups/catalytic_saas_${BACKUP_TIMESTAMP}.dump

# Verify restore
psql catalytic_saas -c "SELECT COUNT(*) FROM tenants;"
psql catalytic_saas -c "SELECT MAX(created_at) FROM tenants;"
```

**SQLite Restore** (if using SQLite):
```bash
# Backup current (corrupted) database
cp catalytic_saas.db catalytic_saas_corrupted_$(date +%Y%m%d_%H%M%S).db

# Restore from backup
cp backups/catalytic_saas_${BACKUP_TIMESTAMP}.db catalytic_saas.db

# Verify integrity
sqlite3 catalytic_saas.db "PRAGMA integrity_check;"
```

### Step 4: Rollback Application Code (7-10 minutes)

```bash
# Identify previous stable version
PREVIOUS_VERSION=$(kubectl rollout history deployment/catalytic-saas-api -n catalytic-saas | tail -2 | head -1 | awk '{print $1}')

# Rollback to specific revision
kubectl rollout undo deployment/catalytic-saas-api -n catalytic-saas --to-revision=${PREVIOUS_VERSION}

# OR use git tag to redeploy previous version
export VERSION="1.0.0"  # Previous stable version
docker pull ${REGISTRY}/catalytic-saas-api:${VERSION}
kubectl set image deployment/catalytic-saas-api \
  catalytic-saas-api=${REGISTRY}/catalytic-saas-api:${VERSION} \
  -n catalytic-saas

# Wait for rollout
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas --timeout=5m
```

### Step 5: Verify Database-App Compatibility (10-12 minutes)

```bash
# Run database integrity checks
kubectl exec -it deployment/catalytic-saas-api -n catalytic-saas -- \
  python scripts/verify_database.py

# Check application logs for database errors
kubectl logs deployment/catalytic-saas-api -n catalytic-saas | grep -i "database\|error"

# Test database operations
kubectl exec -it deployment/catalytic-saas-api -n catalytic-saas -- sh
# Inside pod:
python -c "
from database.models import Tenant
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

engine = create_engine(os.getenv('DATABASE_URL'))
Session = sessionmaker(bind=engine)
session = Session()

# Test query
tenants = session.query(Tenant).all()
print(f'Found {len(tenants)} tenants')
"
```

### Step 6: Resume Traffic (12-13 minutes)

```bash
# Restore ingress
kubectl apply -f kubernetes/ingress.yaml -n catalytic-saas

# Scale up deployment
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=3

# Verify pods are ready
kubectl wait --for=condition=ready pod -l app=catalytic-saas-api -n catalytic-saas --timeout=2m
```

### Step 7: Verify Functionality (13-15 minutes)

```bash
# Run smoke tests
export PRODUCTION_URL=https://api.your-domain.com
cd tests/smoke
./smoke_test_runner.sh

# Manual verification
# 1. Test user registration
curl -X POST https://api.your-domain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rollback-test@example.com",
    "password": "Test123!@#",
    "tenant_name": "RollbackTest"
  }'

# 2. Test user login
curl -X POST https://api.your-domain.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rollback-test@example.com",
    "password": "Test123!@#"
  }'

# 3. Check health
curl https://api.your-domain.com/health
```

### Step 8: Declare All Clear (15 minutes)

```bash
# Notify team
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "✅ ROLLBACK COMPLETE - Service Restored",
    "blocks": [
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "*Rollback Complete*\nService restored to stable version\nAll smoke tests passing"
        }
      }
    ]
  }'

# Update status page
# Mark incident as resolved

# Document in incident report
cat >> docs/incidents/rollback_$(date +%Y%m%d).md <<EOF
# Rollback Incident - $(date)

## Reason
<Describe why rollback was needed>

## Actions Taken
- Stopped traffic at: $(date)
- Database restored to: ${BACKUP_TIMESTAMP}
- Application rolled back to: ${PREVIOUS_VERSION}
- Service restored at: $(date)

## Verification
- Smoke tests: PASSED
- Health checks: GREEN
- User functionality: OPERATIONAL

## Next Steps
- [ ] Root cause analysis
- [ ] Fix and retest
- [ ] Schedule re-deployment
EOF
```

---

## Rollback Decision Matrix

### Decision Tree

```
Is service experiencing issues?
├── Yes → Is error rate > 5%?
│   ├── Yes → ROLLBACK IMMEDIATELY (Level 1 or 3)
│   └── No → Monitor closely
└── No → Continue monitoring

Were database changes made?
├── Yes → Were migrations successful?
│   ├── Yes → Level 1 Rollback (app only)
│   └── No → Level 3 Rollback (app + database)
└── No → Level 1 Rollback (app only)

Are users affected?
├── Severely (can't use service) → ROLLBACK IMMEDIATELY
├── Moderately (degraded performance) → Evaluate and decide
└── Minimally → Fix forward or schedule rollback
```

### Risk Assessment

| Scenario | Rollback Risk | Recommended Action |
|----------|---------------|-------------------|
| App code only changed | Low | Level 1 rollback |
| Config/secrets changed | Low | Level 2 rollback |
| Database migration ran | Medium | Level 3 rollback + restore |
| Data modified by users | High | Careful restore with data merge |
| Multi-service deployment | High | Coordinate rollback across services |

---

## Rollback Validation Checklist

After any rollback, verify:

- [ ] **Application Health**
  - [ ] All pods running: `kubectl get pods -n catalytic-saas`
  - [ ] Health endpoint responding: `curl https://api.your-domain.com/health`
  - [ ] No error logs: `kubectl logs deployment/catalytic-saas-api -n catalytic-saas | grep ERROR`

- [ ] **Database Integrity**
  - [ ] Database accessible: Test connection
  - [ ] Data integrity: Run `PRAGMA integrity_check` (SQLite) or equivalent
  - [ ] Critical tables present: Verify key tables exist
  - [ ] Recent data visible: Check latest records

- [ ] **Critical Workflows**
  - [ ] User registration works
  - [ ] User login works
  - [ ] Lattice creation works
  - [ ] API authentication works
  - [ ] Webhook delivery works

- [ ] **Monitoring & Alerts**
  - [ ] Metrics being collected
  - [ ] No active alerts firing
  - [ ] Grafana dashboards accessible
  - [ ] Error rate < 1%
  - [ ] Response time < 100ms p95

- [ ] **External Services**
  - [ ] Stripe webhooks functional
  - [ ] Email delivery working
  - [ ] Third-party integrations operational

---

## Preventing Future Rollbacks

### Best Practices

1. **Always Use Staging First**
   - Deploy to staging before production
   - Run full test suite on staging
   - Perform load testing on staging
   - Verify database migrations on staging

2. **Database Migration Safety**
   - Always use reversible migrations
   - Test migrations on production-like data
   - Never delete columns (deprecate first)
   - Use feature flags for risky changes

3. **Gradual Rollouts**
   - Deploy to canary environment first (10% traffic)
   - Monitor canary for 30 minutes
   - Gradually increase traffic (25%, 50%, 100%)
   - Roll back canary if issues detected

4. **Automated Rollback**
   - Configure automatic rollback triggers
   - Use Kubernetes progressive delivery (Flagger, Argo Rollouts)
   - Implement circuit breakers
   - Set up automated smoke tests post-deployment

5. **Monitoring & Alerts**
   - Ensure all alerts are configured before deployment
   - Monitor deployment in real-time
   - Set up anomaly detection
   - Alert on deployment failures

---

## Rollback Scripts

### Automated Rollback Script

```bash
#!/bin/bash
# rollback.sh - Automated rollback script

set -e

NAMESPACE="${NAMESPACE:-catalytic-saas}"
BACKUP_TIMESTAMP="${1:-}"
LEVEL="${2:-1}"  # 1=app only, 2=app+config, 3=app+db

echo "Starting Level ${LEVEL} Rollback..."

case ${LEVEL} in
  1)
    echo "Rolling back application only..."
    kubectl rollout undo deployment/catalytic-saas-api -n ${NAMESPACE}
    kubectl rollout status deployment/catalytic-saas-api -n ${NAMESPACE}
    ;;

  2)
    echo "Rolling back application and configuration..."
    kubectl apply -f backups/configmap-backup-latest.yaml
    kubectl rollout undo deployment/catalytic-saas-api -n ${NAMESPACE}
    kubectl rollout restart deployment/catalytic-saas-api -n ${NAMESPACE}
    ;;

  3)
    if [ -z "${BACKUP_TIMESTAMP}" ]; then
      echo "Error: BACKUP_TIMESTAMP required for Level 3 rollback"
      exit 1
    fi

    echo "Full rollback with database restore..."

    # Stop traffic
    kubectl scale deployment/catalytic-saas-api -n ${NAMESPACE} --replicas=0

    # Restore database
    ./scripts/restore-database.sh production ${BACKUP_TIMESTAMP}

    # Rollback app
    kubectl rollout undo deployment/catalytic-saas-api -n ${NAMESPACE}

    # Resume traffic
    kubectl scale deployment/catalytic-saas-api -n ${NAMESPACE} --replicas=3
    ;;

  *)
    echo "Invalid rollback level: ${LEVEL}"
    exit 1
    ;;
esac

# Verify rollback
echo "Verifying rollback..."
kubectl get pods -n ${NAMESPACE}

# Run smoke tests
export PRODUCTION_URL="https://api.your-domain.com"
cd tests/smoke && ./smoke_test_runner.sh

echo "Rollback complete!"
```

### Usage

```bash
# Level 1: Application only
./scripts/rollback.sh

# Level 2: Application + configuration
./scripts/rollback.sh "" 2

# Level 3: Full rollback with database
./scripts/rollback.sh 20251006_120000 3
```

---

## Post-Rollback Actions

### Immediate (Within 1 hour)

1. **Document Incident**
   - Create incident report
   - Document timeline of events
   - Capture logs and metrics
   - Record decisions made

2. **Notify Stakeholders**
   - Send status update to all stakeholders
   - Update status page
   - Post in company Slack/Teams
   - Email affected customers (if any)

3. **Monitor Closely**
   - Watch metrics for 2 hours
   - Verify no residual issues
   - Check user reports
   - Monitor support tickets

### Short-term (Within 24 hours)

1. **Root Cause Analysis**
   - Investigate what went wrong
   - Identify gap in testing
   - Document lessons learned
   - Update runbooks

2. **Fix and Test**
   - Develop fix for root cause
   - Test fix thoroughly
   - Verify on staging
   - Plan re-deployment

3. **Update Processes**
   - Update deployment checklist
   - Improve testing procedures
   - Add new smoke tests
   - Enhance monitoring

### Long-term (Within 1 week)

1. **Post-Mortem**
   - Conduct blameless post-mortem
   - Identify systemic issues
   - Create action items
   - Assign owners

2. **Improve Automation**
   - Automate rollback triggers
   - Enhance smoke tests
   - Improve monitoring coverage
   - Update documentation

---

## Contacts

### Emergency Contacts

| Role | Contact | Availability |
|------|---------|--------------|
| DevOps Lead | oncall-devops@example.com | 24/7 |
| Engineering Lead | oncall-eng@example.com | 24/7 |
| Database Admin | dba@example.com | 24/7 |
| Security Team | security@example.com | 24/7 |
| Product Manager | pm@example.com | Business hours |
| Customer Success | support@example.com | Business hours |

### Escalation Path

1. **Level 1**: On-call engineer (respond: 5 min)
2. **Level 2**: Team lead (respond: 15 min)
3. **Level 3**: VP Engineering (respond: 30 min)
4. **Level 4**: CTO (respond: 1 hour)

---

**Last Updated**: 2025-10-06
**Next Review**: Monthly
**Owner**: DevOps Team
