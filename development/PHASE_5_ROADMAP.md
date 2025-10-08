# Phase 5 Roadmap: Production Hardening
**Created:** October 6, 2025  
**Focus:** CI/CD, Observability & Security  
**Duration:** 6-8 weeks (48-60 hours)  
**Cost:** $0-50/month

---

## 🎯 Executive Summary

Phase 5 transforms your multi-cloud deployment from **automated deployment** to **production-grade operations** by implementing:

1. **Automated CI/CD Pipeline** - GitHub Actions
2. **Comprehensive Observability** - Prometheus + Grafana + Loki
3. **Security Hardening** - Trivy + HashiCorp Vault
4. **Cost Optimization** - OpenCost + Infracost
5. **Progressive Deployment** - Argo Rollouts (blue/green, canary)

---

## 📊 Priority Matrix (What to Do First)

### 🔥 HIGH IMPACT + LOW EFFORT (Do First - Week 1)

| Task | Hours | Cost | Why Critical |
|------|-------|------|--------------|
| GitHub Actions CI/CD | 6h | $0 | Automates everything |
| Trivy Security Scanning | 2h | $0 | Prevents vulnerabilities |
| Prometheus + Grafana | 6h | $0 | Visibility into problems |

**Week 1 Total:** 14 hours, $0 cost

### 💎 HIGH IMPACT + HIGH EFFORT (Strategic - Week 2-4)

| Task | Hours | Cost | Dependencies |
|------|-------|------|--------------|
| HashiCorp Vault | 12h | $0 | Week 1 complete |
| Argo Rollouts | 8h | $0 | Kubernetes cluster |
| Grafana Loki Logging | 4h | $0 | Prometheus setup |

**Week 2-4 Total:** 24 hours, $0 cost

### ⚡ QUICK WINS (Week 2)

| Task | Hours | Cost | Benefit |
|------|-------|------|---------|
| OpenCost | 3h | $0 | Cost visibility |
| Infracost | 2h | $0 | Cost forecasting |
| GitHub Actions Cache | 1h | $0 | Faster builds |

---

## 📅 Week-by-Week Implementation Plan

### Week 1: Foundation (16 hours)

#### Day 1-2: GitHub Actions CI/CD (6 hours)

**Current State:**
- ✅ `.github/workflows/ci-cd.yml` exists with basic pipeline
- ✅ Trivy security scanning included
- ❌ Missing multi-cloud deployment automation

**Tasks:**

1. **Create production deployment workflow** (2h)
   - File: `.github/workflows/deploy-production.yml`
   - Triggers: Push to `main` branch
   - Deploys to: Railway, Render, Fly.io

2. **Create staging deployment workflow** (2h)
   - File: `.github/workflows/deploy-staging.yml`
   - Triggers: Push to `staging` branch
   - Environment: Staging

3. **Create rollback workflow** (2h)
   - File: `.github/workflows/rollback.yml`
   - Triggers: Manual workflow dispatch
   - Action: Redeploys previous version

**Deliverables:**
```
.github/workflows/
├── ci-cd.yml (existing)
├── deploy-production.yml (new)
├── deploy-staging.yml (new)
└── rollback.yml (new)
```

**Success Criteria:**
- ✅ Push to main → auto-deploys to all platforms
- ✅ Build time < 5 minutes
- ✅ One-click rollback available

---

#### Day 3: Security Scanning Enhancement (2 hours)

**Current State:**
- ✅ Trivy scanning exists
- ❌ Doesn't fail builds on critical vulnerabilities

**Tasks:**

1. **Enhance Trivy configuration** (1h)
   ```yaml
   # Add to .github/workflows/ci-cd.yml
   - name: Run Trivy scanner
     uses: aquasecurity/trivy-action@master
     with:
       image-ref: wo1ves/go-deployment-demo:latest
       format: 'sarif'
       exit-code: '1'  # NEW: Fail on high/critical
       severity: 'CRITICAL,HIGH'
   ```

2. **Add SARIF upload for GitHub Security** (1h)
   ```yaml
   - name: Upload Trivy results
     uses: github/codeql-action/upload-sarif@v2
     with:
       sarif_file: 'trivy-results.sarif'
   ```

**Deliverables:**
- Security tab in GitHub shows vulnerabilities
- Builds fail if critical issues found

---

#### Day 4-5: Prometheus + Grafana (8 hours)

**Tasks:**

1. **Enhance Go app metrics** (2h)
   - Add Prometheus client library
   - Instrument HTTP handlers
   - Add custom business metrics

2. **Deploy Prometheus** (3h)
   - Create `k8s/monitoring/prometheus.yaml`
   - Configure scraping for Go app
   - Set up 15-day retention

3. **Deploy Grafana** (2h)
   - Create `k8s/monitoring/grafana.yaml`
   - Connect to Prometheus
   - Import Go app dashboard

4. **Create alerts** (1h)
   - Alert on high error rate (>5%)
   - Alert on high latency (P95 >500ms)
   - Alert on pod crashes

**Deliverables:**
```
k8s/monitoring/
├── prometheus.yaml
├── grafana.yaml
├── prometheus-config.yaml
└── alerts.yaml
```

**Dashboard URL:** `http://localhost:3000` (Grafana)

---

### Week 2: Observability & Cost (12 hours)

#### Day 1-2: Grafana Loki (4 hours)

**Purpose:** Centralized log aggregation

**Tasks:**

1. **Deploy Loki** (2h)
   ```yaml
   # k8s/monitoring/loki.yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: loki
   spec:
     ports:
     - port: 3100
       targetPort: 3100
     selector:
       app: loki
   ```

2. **Configure log shipping** (1h)
   - Install Promtail on each node
   - Configure log collection from pods

3. **Integrate with Grafana** (1h)
   - Add Loki data source
   - Create log dashboard

**Success Criteria:**
- All pod logs visible in Grafana
- Can search logs by label
- Log retention: 30 days

---

#### Day 3: OpenCost (3 hours)

**Purpose:** Kubernetes cost monitoring

**Tasks:**

1. **Deploy OpenCost** (1h)
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/opencost/opencost/develop/kubernetes/opencost.yaml
   ```

2. **Configure cost allocation** (1h)
   - Tag namespaces with teams
   - Set CPU/memory costs

3. **Create cost dashboard** (1h)
   - Cost per service
   - Cost trends over time
   - Cost breakdown by resource

**Dashboard URL:** `http://localhost:9090` (OpenCost UI)

---

#### Day 4: Infracost (2 hours)

**Purpose:** Infrastructure cost estimates in CI/CD

**Tasks:**

1. **Add Infracost to GitHub Actions** (1h)
   ```yaml
   - name: Setup Infracost
     uses: infracost/actions/setup@v2
   
   - name: Generate cost estimate
     run: infracost breakdown --path=k8s/
   ```

2. **Configure pull request comments** (1h)
   - Show cost diff on PRs
   - Alert if cost increases >20%

**Deliverable:** Cost estimates appear on every PR

---

#### Day 5: Grafana Dashboards (3 hours)

**Tasks:**

1. **Go Application Dashboard** (1h)
   - Request rate, latency, error rate
   - P50, P90, P95, P99 latencies
   - Active connections

2. **Infrastructure Dashboard** (1h)
   - CPU/memory usage per pod
   - Network I/O
   - Disk usage

3. **Cost Dashboard** (1h)
   - Daily spend by cloud platform
   - Monthly trends
   - Cost per request

---

### Week 3-4: Security & Progressive Deployments (20 hours)

#### Week 3 Day 1-3: HashiCorp Vault (10 hours)

**Purpose:** Centralized secrets management

**Tasks:**

1. **Deploy Vault to Kubernetes** (3h)
   ```yaml
   # k8s/security/vault.yaml
   apiVersion: apps/v1
   kind: StatefulSet
   metadata:
     name: vault
   spec:
     serviceName: vault
     replicas: 1
     template:
       spec:
         containers:
         - name: vault
           image: hashicorp/vault:latest
   ```

2. **Initialize and unseal Vault** (2h)
   ```bash
   kubectl exec -it vault-0 -- vault operator init
   kubectl exec -it vault-0 -- vault operator unseal
   ```

3. **Configure Kubernetes auth** (2h)
   - Enable Kubernetes auth method
   - Create service account policies
   - Configure pod access

4. **Store secrets in Vault** (2h)
   - Database credentials
   - API keys
   - Docker Hub token
   - Cloud provider credentials

5. **Update deployment scripts** (1h)
   - Remove hardcoded secrets
   - Fetch from Vault instead

**Deliverables:**
- Vault UI: `http://localhost:8200`
- All secrets centralized
- Secrets rotation policy (90 days)

---

#### Week 3 Day 4-5: Vault Integration with Go App (5 hours)

**Tasks:**

1. **Add Vault client to Go app** (2h)
   ```go
   import "github.com/hashicorp/vault/api"
   
   func getSecret(key string) (string, error) {
       client, _ := api.NewClient(&api.Config{
           Address: os.Getenv("VAULT_ADDR"),
       })
       secret, _ := client.Logical().Read("secret/data/app")
       return secret.Data[key].(string), nil
   }
   ```

2. **Update environment variables** (1h)
   - Point to Vault instead of hardcoded values

3. **Test secret retrieval** (2h)
   - Unit tests for Vault integration
   - Integration tests with real Vault

---

#### Week 4 Day 1-3: Argo Rollouts (8 hours)

**Purpose:** Progressive deployments (canary, blue/green)

**Tasks:**

1. **Install Argo Rollouts** (1h)
   ```bash
   kubectl create namespace argo-rollouts
   kubectl apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml
   ```

2. **Convert Deployment to Rollout** (3h)
   ```yaml
   # k8s/rollout.yaml
   apiVersion: argoproj.io/v1alpha1
   kind: Rollout
   metadata:
     name: go-deployment-demo
   spec:
     replicas: 3
     strategy:
       canary:
         steps:
         - setWeight: 20
         - pause: {duration: 1m}
         - setWeight: 50
         - pause: {duration: 1m}
         - setWeight: 80
         - pause: {duration: 1m}
   ```

3. **Configure automated analysis** (2h)
   - Monitor error rate during rollout
   - Auto-rollback if error rate >5%

4. **Test canary deployment** (2h)
   - Deploy new version
   - Verify 20/50/80% traffic split
   - Confirm auto-rollback works

**Deliverables:**
- Canary deployments operational
- Zero-downtime deployments
- Automated rollback on errors

---

#### Week 4 Day 4-5: Documentation & Testing (4 hours)

**Tasks:**

1. **Create Phase 5 documentation** (2h)
   - `PHASE5_GUIDE.md` - Complete guide
   - Architecture diagrams
   - Troubleshooting section

2. **Validation testing** (2h)
   - Test all CI/CD workflows
   - Verify monitoring stack
   - Confirm Vault integration
   - Test canary deployments

---

## 📂 Files to Create

### GitHub Actions Workflows
```
.github/workflows/
├── ci-cd.yml (exists - enhance)
├── deploy-production.yml (new)
├── deploy-staging.yml (new)
└── rollback.yml (new)
```

### Kubernetes Manifests
```
k8s/
├── monitoring/
│   ├── prometheus.yaml
│   ├── prometheus-config.yaml
│   ├── grafana.yaml
│   ├── loki.yaml
│   ├── opencost.yaml
│   └── alerts.yaml
├── security/
│   ├── vault.yaml
│   └── vault-policies.yaml
└── rollout.yaml (replaces deployment.yaml)
```

### Documentation
```
docs/
├── PHASE5_GUIDE.md
├── MONITORING_GUIDE.md
├── SECURITY_GUIDE.md
└── PROGRESSIVE_DEPLOYMENT_GUIDE.md
```

---

## 💰 Cost Breakdown

### Recommended Stack (100% Free)
| Component | Monthly Cost | Why This Choice |
|-----------|--------------|-----------------|
| GitHub Actions | $0 | Public repo = 2,000 min/month free |
| Prometheus + Grafana | $0 | Self-hosted on existing K8s |
| Trivy | $0 | Open-source security scanning |
| HashiCorp Vault | $0 | OSS version sufficient |
| OpenCost | $0 | CNCF project, free forever |
| Argo Rollouts | $0 | Open-source by Argo Project |
| **TOTAL** | **$0/month** | **$0/year** |

### Optional Managed Services
| Component | Monthly Cost | Benefit |
|-----------|--------------|---------|
| Grafana Cloud | $19 | Managed, no K8s needed |
| GitHub Actions (private repo) | $8 | 3,000 minutes/month |
| **TOTAL** | **$27/month** | **$324/year** |

---

## 📈 Success Metrics

### Week 1 Goals
- [ ] CI/CD pipeline deploys to all clouds automatically
- [ ] Build time < 5 minutes
- [ ] Security scans fail builds on critical issues
- [ ] Prometheus collecting metrics from Go app
- [ ] Grafana displaying basic dashboard

### Week 2 Goals
- [ ] All logs centralized in Loki
- [ ] Cost visibility via OpenCost
- [ ] Infracost commenting on PRs
- [ ] 5+ custom Grafana dashboards

### Week 3-4 Goals
- [ ] Zero secrets in code or config files
- [ ] Vault managing all sensitive data
- [ ] Canary deployments working
- [ ] Auto-rollback on high error rate
- [ ] Complete documentation

---

## 🎯 Expected Outcomes

### After Week 1
- **Deployment Frequency:** Multiple per day (vs manual before)
- **Build Reliability:** >95% success rate
- **Security Posture:** 100% container scanning
- **Visibility:** Real-time metrics from all services

### After Week 2
- **Observability:** Logs + metrics + alerts
- **Cost Awareness:** Know exactly what you're spending
- **Alert Response:** <5 minutes to detect issues

### After Week 3-4
- **Zero Downtime:** Canary deployments
- **Security Compliance:** No hardcoded secrets
- **Reliability:** Auto-rollback prevents outages
- **Scalability:** Ready for 10x traffic

---

## 🚧 Prerequisites

### Before Starting Week 1:
- [ ] Docker running
- [ ] Kubernetes cluster access (or Minikube)
- [ ] GitHub account
- [ ] Docker Hub account (wo1ves)

### Before Starting Week 3:
- [ ] Monitoring stack operational (from Week 1-2)
- [ ] Kubernetes namespace created: `vault`
- [ ] Kubernetes namespace created: `argo-rollouts`

---

## 🔄 Next Steps After Phase 5

### Phase 6 Candidates (Future):
1. **Service Mesh** (Linkerd) - Advanced traffic management
2. **Multi-Region Deployment** - Geographic distribution
3. **Database Integration** - PostgreSQL with backups
4. **Advanced Monitoring** - Distributed tracing (Jaeger)
5. **Chaos Engineering** - Resilience testing

---

## 🆘 Troubleshooting

### Common Issues

**Issue:** GitHub Actions failing
```bash
# Check logs
gh run list
gh run view RUN_ID

# Re-run failed jobs
gh run rerun RUN_ID
```

**Issue:** Prometheus not scraping metrics
```bash
# Check Prometheus targets
kubectl port-forward -n monitoring svc/prometheus 9090:9090
# Visit: http://localhost:9090/targets
```

**Issue:** Vault sealed after restart
```bash
# Unseal Vault
kubectl exec -it vault-0 -- vault operator unseal UNSEAL_KEY
```

---

## 📚 Resources

### Official Documentation
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Prometheus Docs](https://prometheus.io/docs/)
- [Grafana Docs](https://grafana.com/docs/)
- [Vault Docs](https://www.vaultproject.io/docs)
- [Argo Rollouts Docs](https://argoproj.github.io/argo-rollouts/)

### Tutorials
- [Prometheus + Grafana Setup](https://prometheus.io/docs/visualization/grafana/)
- [HashiCorp Vault on Kubernetes](https://learn.hashicorp.com/tutorials/vault/kubernetes-raft-deployment-guide)
- [Progressive Delivery with Argo](https://argoproj.github.io/argo-rollouts/getting-started/)

---

## ✅ Phase 5 Checklist

Copy this to track your progress:

```markdown
### Week 1: Foundation
- [ ] GitHub Actions enhanced (deploy-production.yml)
- [ ] Security scanning fails on critical issues
- [ ] Prometheus deployed and scraping metrics
- [ ] Grafana deployed with basic dashboard

### Week 2: Observability & Cost
- [ ] Loki deployed for log aggregation
- [ ] OpenCost deployed for cost visibility
- [ ] Infracost integrated in CI/CD
- [ ] 5+ Grafana dashboards created

### Week 3: Security
- [ ] Vault deployed to Kubernetes
- [ ] Vault initialized and unsealed
- [ ] All secrets migrated to Vault
- [ ] Go app integrated with Vault

### Week 4: Progressive Deployments
- [ ] Argo Rollouts installed
- [ ] Rollout manifest created
- [ ] Canary deployment tested
- [ ] Auto-rollback verified
- [ ] Documentation complete
```

---

**Ready to Start?** Begin with Week 1, Day 1: GitHub Actions CI/CD Enhancement

---

**Created:** October 6, 2025  
**Status:** Ready to Execute  
**Estimated Completion:** November 17, 2025 (6 weeks)  
**Total Investment:** 48-60 hours, $0-50/month
