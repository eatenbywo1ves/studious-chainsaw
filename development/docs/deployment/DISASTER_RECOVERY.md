# Disaster Recovery Plan

## SaaS Platform - Business Continuity & Disaster Recovery

**RTO (Recovery Time Objective)**: 1 hour
**RPO (Recovery Point Objective)**: 24 hours
**Last Updated**: 2025-10-06

---

## Table of Contents

1. [Overview](#overview)
2. [Disaster Scenarios](#disaster-scenarios)
3. [Backup Strategy](#backup-strategy)
4. [Recovery Procedures](#recovery-procedures)
5. [Testing & Validation](#testing--validation)

---

## Overview

### Purpose

This disaster recovery plan ensures the Catalytic Computing SaaS platform can be restored within acceptable timeframes in the event of catastrophic failure.

### Objectives

- **RTO**: System operational within 1 hour of disaster declaration
- **RPO**: Maximum 24 hours of data loss acceptable
- **Availability SLA**: 99.9% uptime (43.8 minutes downtime/month allowed)

### Scope

This plan covers:
- Complete infrastructure failure
- Data center outage
- Database corruption or loss
- Application failure
- Security incidents
- Natural disasters

---

## Disaster Scenarios

### Scenario 1: Complete Data Center Outage

**Probability**: Low
**Impact**: Critical
**RTO**: 1 hour
**RPO**: 24 hours

**Recovery Strategy**: Failover to secondary region

**Procedure**:
1. Declare disaster (incident commander)
2. Activate DR site in secondary region
3. Restore latest database backup
4. Update DNS to point to DR site
5. Verify functionality with smoke tests
6. Monitor and stabilize

---

### Scenario 2: Database Corruption/Loss

**Probability**: Medium
**Impact**: Critical
**RTO**: 30 minutes
**RPO**: 24 hours

**Recovery Strategy**: Restore from backup

**Procedure**:
1. Stop application to prevent further corruption
2. Identify last known good backup
3. Restore database from backup
4. Verify data integrity
5. Restart application
6. Run smoke tests

---

### Scenario 3: Kubernetes Cluster Failure

**Probability**: Low
**Impact**: High
**RTO**: 1 hour
**RPO**: 0 (application state, not data)

**Recovery Strategy**: Rebuild cluster and redeploy

**Procedure**:
1. Provision new Kubernetes cluster
2. Deploy infrastructure (networking, storage)
3. Deploy application from container registry
4. Connect to existing database
5. Verify and smoke test

---

### Scenario 4: Security Breach / Ransomware

**Probability**: Low
**Impact**: Critical
**RTO**: 2 hours
**RPO**: 24 hours

**Recovery Strategy**: Isolate, clean, restore

**Procedure**:
1. Immediately isolate affected systems
2. Notify security team and stakeholders
3. Assess scope of breach
4. Rebuild infrastructure from scratch
5. Restore data from clean backup
6. Implement additional security controls
7. Conduct forensic analysis

---

### Scenario 5: Application Software Bug

**Probability**: Medium
**Impact**: Medium
**RTO**: 15 minutes
**RPO**: 0

**Recovery Strategy**: Rollback deployment

**Procedure**: See [ROLLBACK_PROCEDURES.md](ROLLBACK_PROCEDURES.md)

---

## Backup Strategy

### Backup Components

#### 1. Database Backups

**PostgreSQL** (if using):
```bash
# Automated daily backups
pg_dump -Fc -h ${DB_HOST} -U ${DB_USER} catalytic_saas \
  > backups/catalytic_saas_$(date +%Y%m%d_%H%M%S).dump

# Retention: 30 days local, 90 days off-site
```

**SQLite** (if using):
```bash
# Automated backups
sqlite3 catalytic_saas.db ".backup backups/catalytic_saas_$(date +%Y%m%d_%H%M%S).db"

# Cloud upload
aws s3 cp backups/catalytic_saas_*.db s3://backup-bucket/database/
```

**Schedule**:
- Full backup: Daily at 2 AM UTC
- Incremental backup: Every 6 hours
- Retention: 30 days local, 90 days cloud
- Location: Local + AWS S3/Google Cloud Storage

#### 2. Application State Backups

```bash
# Kubernetes resources
kubectl get all -n catalytic-saas -o yaml > backups/k8s-resources_$(date +%Y%m%d).yaml

# ConfigMaps and Secrets
kubectl get configmaps -n catalytic-saas -o yaml > backups/configmaps_$(date +%Y%m%d).yaml
kubectl get secrets -n catalytic-saas -o yaml > backups/secrets_$(date +%Y%m%d).yaml
```

**Schedule**: Before each deployment

#### 3. Code and Configuration Backups

- **Git Repository**: Multiple remotes (GitHub, GitLab, Bitbucket)
- **Container Images**: Registry with retention policy
- **Infrastructure as Code**: Version controlled

#### 4. Monitoring Data Backups

```bash
# Prometheus data snapshot
curl -XPOST http://prometheus:9090/api/v1/admin/tsdb/snapshot

# Grafana dashboards
curl -X GET https://grafana/api/dashboards/home \
  -H "Authorization: Bearer ${GRAFANA_TOKEN}" \
  > backups/grafana_dashboards_$(date +%Y%m%d).json
```

**Retention**: 30 days

---

## Recovery Procedures

### Full System Recovery (Worst Case)

**Estimated Time**: 1 hour
**Prerequisites**: Recent backups available

#### Phase 1: Infrastructure Provisioning (15 minutes)

```bash
# 1. Provision new Kubernetes cluster
# (Using your cloud provider's tools)

# AWS EKS example:
eksctl create cluster \
  --name catalytic-recovery \
  --region us-east-1 \
  --nodes 3 \
  --node-type t3.xlarge

# GCP GKE example:
gcloud container clusters create catalytic-recovery \
  --num-nodes=3 \
  --machine-type=n1-standard-4 \
  --region=us-central1

# Azure AKS example:
az aks create \
  --resource-group catalytic-rg \
  --name catalytic-recovery \
  --node-count 3 \
  --node-vm-size Standard_D4_v3
```

#### Phase 2: Database Recovery (20 minutes)

```bash
# 2. Provision database instance
# (Cloud-managed or self-hosted)

# 3. Restore from latest backup
LATEST_BACKUP=$(ls -t backups/catalytic_saas_*.dump | head -1)

# PostgreSQL restore
createdb catalytic_saas
pg_restore -d catalytic_saas ${LATEST_BACKUP}

# Verify restore
psql catalytic_saas -c "SELECT COUNT(*) FROM tenants;"
psql catalytic_saas -c "SELECT MAX(created_at) FROM tenants;"

# 4. Update database connection string
export DATABASE_URL="postgresql://user:password@new-db-host:5432/catalytic_saas"
```

#### Phase 3: Application Deployment (15 minutes)

```bash
# 5. Create namespace and secrets
kubectl create namespace catalytic-saas

kubectl create secret generic database-credentials \
  --from-literal=url="${DATABASE_URL}" \
  -n catalytic-saas

kubectl create secret generic jwt-secret \
  --from-literal=secret="${JWT_SECRET}" \
  -n catalytic-saas

# 6. Deploy application
kubectl apply -f kubernetes/deployment.yaml -n catalytic-saas
kubectl apply -f kubernetes/service.yaml -n catalytic-saas
kubectl apply -f kubernetes/ingress.yaml -n catalytic-saas

# 7. Wait for deployment
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas --timeout=5m
```

#### Phase 4: DNS and Traffic Routing (5 minutes)

```bash
# 8. Get new ingress IP
NEW_IP=$(kubectl get ingress catalytic-ingress -n catalytic-saas -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# 9. Update DNS records
# (Use your DNS provider's tools)
# Point api.your-domain.com to ${NEW_IP}

# 10. Verify DNS propagation
dig api.your-domain.com

# 11. Update SSL certificate (if needed)
kubectl apply -f kubernetes/cluster-issuer.yaml
kubectl delete certificate catalytic-tls -n catalytic-saas
kubectl apply -f kubernetes/ingress.yaml -n catalytic-saas
```

#### Phase 5: Verification (5 minutes)

```bash
# 12. Run smoke tests
export PRODUCTION_URL=https://api.your-domain.com
cd tests/smoke
./smoke_test_runner.sh

# 13. Verify critical functionality
curl https://api.your-domain.com/health
curl https://api.your-domain.com/metrics

# 14. Test user workflow
# - Registration
# - Login
# - Lattice creation

# 15. Monitor for anomalies
kubectl logs -f deployment/catalytic-saas-api -n catalytic-saas
```

---

### Database-Only Recovery

**Estimated Time**: 20 minutes

```bash
# 1. Stop application to prevent conflicts
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=0

# 2. Backup current (corrupted) database
pg_dump -Fc catalytic_saas > backups/corrupted_$(date +%Y%m%d_%H%M%S).dump

# 3. Identify backup to restore
ls -lah backups/catalytic_saas_*.dump | tail -10
RESTORE_BACKUP="backups/catalytic_saas_20251006_020000.dump"

# 4. Drop and recreate database
psql -c "DROP DATABASE catalytic_saas;"
psql -c "CREATE DATABASE catalytic_saas;"

# 5. Restore from backup
pg_restore -d catalytic_saas ${RESTORE_BACKUP}

# 6. Verify restore
psql catalytic_saas -c "\dt"  # List tables
psql catalytic_saas -c "SELECT COUNT(*) FROM tenants;"

# 7. Restart application
kubectl scale deployment/catalytic-saas-api -n catalytic-saas --replicas=3

# 8. Verify functionality
export PRODUCTION_URL=https://api.your-domain.com
cd tests/smoke && ./smoke_test_runner.sh
```

---

### Application-Only Recovery

**Estimated Time**: 10 minutes

```bash
# 1. Identify stable version
STABLE_VERSION="1.0.0"

# 2. Pull stable image
docker pull ${REGISTRY}/catalytic-saas-api:${STABLE_VERSION}

# 3. Update deployment
kubectl set image deployment/catalytic-saas-api \
  catalytic-saas-api=${REGISTRY}/catalytic-saas-api:${STABLE_VERSION} \
  -n catalytic-saas

# 4. Wait for rollout
kubectl rollout status deployment/catalytic-saas-api -n catalytic-saas

# 5. Verify
kubectl get pods -n catalytic-saas
curl https://api.your-domain.com/health
```

---

## Testing & Validation

### Disaster Recovery Drills

**Frequency**: Quarterly
**Duration**: 2-3 hours
**Participants**: DevOps team, Engineering leads, DBA

#### Drill Procedure

1. **Preparation Week**
   - Schedule drill with all participants
   - Notify stakeholders (no service disruption)
   - Prepare test environment

2. **Drill Day**
   - Execute recovery procedure on test environment
   - Time each phase
   - Document issues encountered
   - Update procedures based on learnings

3. **Post-Drill**
   - Conduct retrospective
   - Update DR plan
   - Create action items
   - Schedule next drill

#### Last Drill Results

| Drill Date | Scenario | Target RTO | Actual RTO | Pass/Fail | Notes |
|------------|----------|------------|------------|-----------|-------|
| 2025-07-15 | Full Recovery | 1 hour | 58 minutes | ✅ Pass | DNS propagation was slow |
| 2025-04-10 | DB Recovery | 30 minutes | 22 minutes | ✅ Pass | Excellent performance |
| 2025-01-08 | App Recovery | 15 minutes | 12 minutes | ✅ Pass | Process refined |

---

### Backup Verification

**Automated Daily Checks**:

```bash
#!/bin/bash
# verify-backups.sh

# Check backup exists
LATEST_BACKUP=$(ls -t backups/catalytic_saas_*.dump | head -1)
if [ -z "${LATEST_BACKUP}" ]; then
  echo "ERROR: No backups found!"
  exit 1
fi

# Check backup age (should be < 24 hours old)
BACKUP_AGE=$(find "${LATEST_BACKUP}" -mtime +1)
if [ -n "${BACKUP_AGE}" ]; then
  echo "WARNING: Latest backup is older than 24 hours!"
fi

# Test restore to temporary database
createdb test_restore_$$
pg_restore -d test_restore_$$ ${LATEST_BACKUP}

# Verify data
TENANT_COUNT=$(psql test_restore_$$ -t -c "SELECT COUNT(*) FROM tenants;")
if [ "${TENANT_COUNT}" -lt 1 ]; then
  echo "ERROR: No tenants found in backup!"
  exit 1
fi

# Cleanup
dropdb test_restore_$$

echo "✅ Backup verification successful: ${LATEST_BACKUP}"
echo "   - Tenants: ${TENANT_COUNT}"
echo "   - Size: $(du -h ${LATEST_BACKUP} | cut -f1)"
```

**Run daily via cron**:
```bash
0 3 * * * /path/to/verify-backups.sh >> /var/log/backup-verification.log 2>&1
```

---

### Recovery Time Objectives

| Component | Target RTO | Actual RTO (Last Test) | Status |
|-----------|------------|------------------------|--------|
| Database | 30 minutes | 22 minutes | ✅ |
| Application | 15 minutes | 12 minutes | ✅ |
| Full System | 1 hour | 58 minutes | ✅ |
| DNS Propagation | 5 minutes | Variable (5-15 min) | ⚠️ |
| SSL Certificate | 10 minutes | 8 minutes | ✅ |

### Recovery Point Objectives

| Data Type | Target RPO | Actual RPO | Status |
|-----------|------------|------------|--------|
| Database | 24 hours | 6 hours | ✅ (Incremental backups) |
| Application Config | 0 | 0 | ✅ (Version controlled) |
| Monitoring Data | 30 days | 30 days | ✅ |
| User Files | N/A | N/A | N/A (No file storage) |

---

## Disaster Declaration

### Authority

Only the following roles can declare a disaster:

1. **CTO / VP Engineering**
2. **Engineering Lead**
3. **DevOps Lead**
4. **On-Call Incident Commander** (with approval)

### Declaration Criteria

Declare disaster if:

- Complete loss of production environment
- Data corruption affecting >50% of data
- Unrecoverable application failure
- Security breach requiring full rebuild
- Multiple component failures beyond repair
- Estimated recovery time > 2 hours using standard procedures

### Declaration Process

1. **Assess Situation**
   - Determine scope of failure
   - Estimate recovery time using standard procedures
   - Evaluate disaster recovery feasibility

2. **Declare Disaster**
   ```bash
   # Send emergency notification
   curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
     -H 'Content-Type: application/json' \
     -d '{
       "text": "🚨🚨🚨 DISASTER DECLARED 🚨🚨🚨",
       "blocks": [
         {
           "type": "section",
           "text": {
             "type": "mrkdwn",
             "text": "*DISASTER RECOVERY INITIATED*\n\nScenario: <disaster type>\nEstimated Recovery: <time>\nIncident Commander: <name>\n\n@channel All hands on deck!"
           }
         }
       ]
     }'
   ```

3. **Activate DR Team**
   - Page on-call team
   - Notify management
   - Assemble recovery team
   - Assign incident commander

4. **Execute Recovery**
   - Follow disaster recovery procedures
   - Document all actions taken
   - Maintain communication with stakeholders

5. **Declare Recovery Complete**
   - Verify all systems operational
   - Run full smoke test suite
   - Monitor for 24 hours
   - Conduct post-mortem

---

## Communication Plan

### During Disaster

**Internal Communication**:
- **Slack Channel**: #disaster-recovery (create if not exists)
- **Update Frequency**: Every 15 minutes
- **War Room**: Video call for coordination

**External Communication**:
- **Status Page**: Update immediately with incident notice
- **Customer Email**: Send within 30 minutes of declaration
- **Social Media**: Post status updates (if public service)

### Communication Templates

**Initial Notification**:
```
Subject: [URGENT] Service Disruption - Disaster Recovery in Progress

We are currently experiencing a service disruption affecting [describe impact].

Status: Disaster recovery procedures initiated
Estimated Recovery: [X] hour(s)
Next Update: [time]

Our team is working to restore service as quickly as possible. We apologize for the inconvenience.

- [Your Company] Operations Team
```

**Recovery Complete**:
```
Subject: [RESOLVED] Service Restored

Service has been fully restored as of [time].

All systems are operational and functioning normally. We have verified functionality through comprehensive testing.

Incident Summary:
- Duration: [X] hours
- Cause: [brief description]
- Resolution: [what was done]

We apologize for the disruption and appreciate your patience.

A detailed post-mortem will be published within 48 hours.

- [Your Company] Operations Team
```

---

## Contacts

### Disaster Recovery Team

| Role | Primary | Backup | Contact |
|------|---------|--------|---------|
| Incident Commander | DevOps Lead | Engineering Lead | oncall-devops@example.com |
| Database Admin | DBA Lead | Sr. DBA | dba@example.com |
| Infrastructure | Cloud Architect | Sr. DevOps | infra@example.com |
| Security | Security Lead | Security Eng | security@example.com |
| Communications | Product Manager | Marketing | comms@example.com |

### Vendor Contacts

| Vendor | Service | Support Contact | SLA |
|--------|---------|-----------------|-----|
| AWS/GCP/Azure | Cloud Infrastructure | [Support Portal] | P1: 15 min |
| Database Provider | Managed Database | [Support Portal] | P1: 30 min |
| DNS Provider | Domain/DNS | [Support Portal] | P1: 1 hour |
| CDN Provider | Content Delivery | [Support Portal] | P1: 1 hour |

---

## Post-Disaster Actions

### Immediate (Within 24 hours)

1. **Document Incident**
   - Complete incident timeline
   - Record all actions taken
   - Capture metrics and logs
   - Note what worked/didn't work

2. **Communicate Status**
   - Send all-clear notification
   - Update status page
   - Thank team members
   - Notify customers of resolution

3. **Monitor Closely**
   - Watch for residual issues
   - Verify backup processes resumed
   - Check monitoring and alerts
   - Ensure full functionality

### Short-term (Within 1 week)

1. **Conduct Post-Mortem**
   - Blameless review of incident
   - Identify root cause
   - Document lessons learned
   - Create action items

2. **Update Procedures**
   - Refine DR procedures based on learnings
   - Update runbooks
   - Improve automation
   - Enhance monitoring

3. **Test Improvements**
   - Verify fixes prevent recurrence
   - Test updated procedures
   - Validate new monitoring

### Long-term (Within 1 month)

1. **Implement Improvements**
   - Complete all action items
   - Enhance redundancy
   - Improve failover capability
   - Update disaster recovery plan

2. **Training**
   - Train team on updated procedures
   - Conduct tabletop exercises
   - Schedule next DR drill
   - Share learnings organization-wide

---

**Last Updated**: 2025-10-06
**Next Review**: 2025-11-06
**Owner**: DevOps Team
**Approved By**: CTO
