# Consolidated Execution Plan 2025
**Created:** October 7, 2025
**Integration:** 3 Major Roadmaps
**Duration:** 12 weeks (October - December 2025)
**Total Investment:** 200-250 hours

---

## Executive Summary

This plan consolidates three parallel initiatives into a **strategic 12-week execution plan** that maximizes synergy while minimizing resource conflicts:

1. **Security Framework** (Production Hardening) - Foundation
2. **Infrastructure** (CI/CD & Observability) - Enabler
3. **Ghidra Plugins** (AI/ML Development) - Innovation

**Key Strategy:** Complete security/infrastructure foundation FIRST, then leverage stable platform for rapid plugin development.

---

## Strategic Dependencies

```
Week 1-4: Security & Infrastructure (Foundation)
    ↓
    ↓ Stable platform enables →
    ↓
Week 5-12: Ghidra Plugin Development (Innovation)
```

**Why This Order?**
- Security framework needs load testing → requires monitoring stack
- CI/CD pipeline accelerates plugin development
- Stable infrastructure = faster iteration on AI features

---

## Phase 1: Foundation (Weeks 1-4)
**Focus:** Security hardening + production infrastructure
**Hours:** 80-100 hours
**Deliverables:** Production-ready platform

### Week 1: Security Testing & Monitoring Foundation (20 hours)

#### Day 1-2: Load Testing Execution (8 hours)
**Roadmap:** Security Framework (Capability Assessment)
**Priority:** CRITICAL - Blocks production validation

**Tasks:**
- [ ] Set up Locust/K6 load testing environment (2h)
- [ ] Execute 1,000 concurrent user test (2h)
- [ ] Execute 10,000 concurrent user test (2h)
- [ ] Analyze bottlenecks and document findings (2h)

**Success Criteria:**
- ✅ 99%+ success rate at 1,000 users
- ✅ 95%+ success rate at 10,000 users
- ✅ P95 latency < 500ms
- ✅ Identify any bottlenecks

**Deliverables:**
- `development/security/load_tests/WEEK3_LOAD_TEST_RESULTS.md`
- Performance optimization recommendations

---

#### Day 3-4: Monitoring Stack Deployment (8 hours)
**Roadmap:** Phase 5 (Week 1)
**Priority:** HIGH - Enables observability

**Tasks:**
- [ ] Deploy Prometheus to development environment (3h)
- [ ] Deploy Grafana with data source connection (2h)
- [ ] Create security metrics dashboard (2h)
- [ ] Configure basic alert rules (1h)

**Dashboards:**
1. **Security Overview Dashboard**
   - Authentication requests/sec
   - Rate limit rejections
   - Token operations (issue/verify/revoke)
   - Redis operation latency

2. **Infrastructure Dashboard**
   - CPU/memory per service
   - Network I/O
   - Request latency (P50, P90, P95, P99)

**Alert Rules:**
- Redis down (critical)
- High rate limit rejection rate (>10% of requests)
- Token verification errors (>5%)
- P95 latency > 500ms

**Deliverables:**
- `development/monitoring/grafana/dashboards/security-overview.json`
- `development/monitoring/prometheus-rules.yml`

---

#### Day 5: Quick Wins & Documentation (4 hours)
**Roadmap:** Security Framework + Phase 5

**Tasks:**
- [ ] Deploy Swagger UI for API docs (1h)
- [ ] Configure basic health check monitoring (1h)
- [ ] Document Week 1 results (2h)

**Deliverables:**
- Swagger UI accessible at `http://localhost:8080/docs`
- `development/WEEK1_EXECUTION_SUMMARY.md`

---

### Week 2: CI/CD Enhancement & Observability (24 hours)

#### Day 1-2: GitHub Actions Enhancement (8 hours)
**Roadmap:** Phase 5 (Week 1)
**Priority:** HIGH - Automates everything

**Tasks:**
- [ ] Create `deploy-production.yml` workflow (3h)
- [ ] Create `deploy-staging.yml` workflow (2h)
- [ ] Create `rollback.yml` workflow (2h)
- [ ] Test all workflows end-to-end (1h)

**Workflows:**

1. **Production Deployment** (`.github/workflows/deploy-production.yml`)
   ```yaml
   Triggers: Push to 'main' branch
   Steps:
     1. Run all tests (unit + E2E + chaos)
     2. Security scan (Trivy)
     3. Build Docker image
     4. Push to Docker Hub
     5. Deploy to Railway
     6. Deploy to Render
     7. Deploy to Fly.io
     8. Smoke test all deployments
   ```

2. **Staging Deployment** (`.github/workflows/deploy-staging.yml`)
   ```yaml
   Triggers: Push to 'staging' branch
   Steps:
     1. Run tests
     2. Deploy to staging environment
     3. Integration tests
   ```

3. **Rollback Workflow** (`.github/workflows/rollback.yml`)
   ```yaml
   Triggers: Manual workflow dispatch
   Inputs:
     - version: Previous version tag
   Steps:
     1. Pull previous Docker image
     2. Deploy to all platforms
     3. Verify rollback success
   ```

**Success Criteria:**
- ✅ Push to main → auto-deploys to all platforms
- ✅ Build time < 5 minutes
- ✅ One-click rollback functional
- ✅ Failed builds block deployment

---

#### Day 3: Advanced Observability (8 hours)
**Roadmap:** Phase 5 (Week 2)

**Tasks:**
- [ ] Deploy Grafana Loki for log aggregation (4h)
- [ ] Configure Promtail for log collection (2h)
- [ ] Create log dashboard in Grafana (2h)

**Log Pipeline:**
```
Application Logs → Promtail → Loki → Grafana
                     ↓
                Query by:
                - Service name
                - Log level (ERROR, WARN, INFO)
                - Time range
                - Text search
```

**Deliverables:**
- `development/monitoring/loki.yaml`
- Log retention: 30 days
- Searchable logs in Grafana

---

#### Day 4: Cost Visibility (5 hours)
**Roadmap:** Phase 5 (Week 2)

**Tasks:**
- [ ] Deploy OpenCost to Kubernetes (2h)
- [ ] Integrate Infracost with GitHub Actions (2h)
- [ ] Create cost dashboard (1h)

**Cost Tracking:**
- Daily spend by service
- Monthly cost trends
- Cost per request/user
- Infrastructure cost forecasting

**Deliverables:**
- OpenCost UI accessible
- Infracost comments on PRs showing cost impact

---

#### Day 5: Custom Dashboards (3 hours)
**Roadmap:** Phase 5 (Week 2)

**Tasks:**
- [ ] Create comprehensive security dashboard (2h)
- [ ] Create business metrics dashboard (1h)

**Dashboards:**
1. **Security Operations Dashboard**
   - Failed login attempts (by IP)
   - DDoS protection events
   - API abuse patterns
   - Token revocation events

2. **Business Metrics Dashboard**
   - Active users
   - API calls per user
   - Registration rate
   - Tenant growth

**Deliverables:**
- 5+ Grafana dashboards deployed

---

### Week 3: Security Hardening (18 hours)

#### Day 1-3: HashiCorp Vault Deployment (12 hours)
**Roadmap:** Phase 5 (Week 3-4)
**Priority:** HIGH - Eliminates hardcoded secrets

**Tasks:**
- [ ] Deploy Vault to Kubernetes (3h)
- [ ] Initialize and unseal Vault (2h)
- [ ] Configure Kubernetes auth method (2h)
- [ ] Migrate all secrets to Vault (3h)
- [ ] Update deployment scripts (2h)

**Secrets to Migrate:**
```
Current (.env files) → Vault Storage:
- SESSION_SECRET_KEY → secret/app/session
- CSRF_SECRET_KEY → secret/app/csrf
- REDIS_PASSWORD → secret/redis/password
- JWT_PRIVATE_KEY → secret/jwt/private
- JWT_PUBLIC_KEY → secret/jwt/public
- DATABASE_URL → secret/database/url
- Docker Hub credentials → secret/docker/credentials
```

**Rotation Policy:**
- Automatic rotation: Every 90 days
- Manual rotation: On-demand via Vault UI
- Zero-downtime rotation: Rolling restart

**Deliverables:**
- `development/security/deployment/vault.yaml`
- Vault UI: `http://localhost:8200`
- All secrets centralized
- Zero secrets in codebase or .env files

---

#### Day 4-5: Performance Optimization (6 hours)
**Roadmap:** Security Framework (Post-Load Testing)

**Tasks:**
- [ ] Analyze load test bottlenecks (2h)
- [ ] Optimize Redis connection pooling (2h)
- [ ] Fine-tune rate limiting thresholds (1h)
- [ ] Re-test after optimizations (1h)

**Optimization Targets:**
- Redis connection pool: 100 connections/worker
- Token verification: < 3ms P95
- Rate limit check: < 5ms P95
- Overall request: < 50ms P95

**Deliverables:**
- `development/PERFORMANCE_OPTIMIZATION_REPORT.md`
- Updated configuration files

---

### Week 4: Progressive Deployments & Validation (18 hours)

#### Day 1-3: Argo Rollouts (10 hours)
**Roadmap:** Phase 5 (Week 4)
**Priority:** MEDIUM - Zero-downtime deployments

**Tasks:**
- [ ] Install Argo Rollouts to Kubernetes (1h)
- [ ] Convert Deployment to Rollout manifest (3h)
- [ ] Configure canary deployment strategy (3h)
- [ ] Configure automated analysis (2h)
- [ ] Test canary deployment end-to-end (1h)

**Canary Strategy:**
```yaml
Rollout Steps:
  1. Deploy 20% traffic to new version (pause 1 min)
  2. Check error rate < 5%
  3. Deploy 50% traffic (pause 1 min)
  4. Check error rate < 5%
  5. Deploy 80% traffic (pause 1 min)
  6. Check error rate < 5%
  7. Deploy 100% (complete)

Auto-Rollback Triggers:
  - Error rate > 5%
  - P95 latency > 500ms
  - Manual abort
```

**Deliverables:**
- `development/kubernetes/rollout.yaml`
- Zero-downtime deployment capability
- Automated rollback on errors

---

#### Day 4-5: Production Validation (8 hours)
**Roadmap:** Security Framework + Phase 5

**Tasks:**
- [ ] Complete production deployment checklist (3h)
- [ ] Execute full system validation (3h)
- [ ] Create incident response runbook (2h)

**Production Checklist:**
- [x] Load testing complete (10,000 users)
- [x] Monitoring stack deployed
- [x] CI/CD pipeline functional
- [x] Secrets in Vault
- [ ] Canary deployments working
- [ ] Alert rules configured
- [ ] Documentation complete
- [ ] Incident runbook created
- [ ] Rollback procedure tested
- [ ] Production deployment guide finalized

**Deliverables:**
- `development/PRODUCTION_DEPLOYMENT_GUIDE.md`
- `development/INCIDENT_RESPONSE_RUNBOOK.md`
- **Production readiness: 100%**

---

## Phase 2: Innovation (Weeks 5-12)
**Focus:** Ghidra plugin development (AI/ML focus)
**Hours:** 120-150 hours
**Deliverables:** 4-6 production plugins

### Strategic Approach: AI-First Strategy

**Rationale:**
- Aligns with 2025 industry trends (AI/ML in reverse engineering)
- Leverages stable CI/CD pipeline for rapid iteration
- Differentiates from traditional analyzers
- High visibility and adoption potential

---

### Week 5-6: GhidrAssist Completion (16 hours)
**Roadmap:** Plugin Roadmap (TIER 0 - Highest Priority)
**ROI Score:** 95/100

#### Current Status
- ✅ MCP integration framework
- ✅ Basic function analysis
- ⚠️ Partial UI implementation
- ❌ Missing key features

#### Missing Features (Implementation Order)

**Week 5 (8 hours):**
- [ ] Function explanation UI (3h)
  - Right-click context menu
  - "Explain Function" → AI-generated explanation
  - Display in dockable window

- [ ] Variable renaming automation (3h)
  - AI suggests meaningful variable names
  - Batch rename approval UI
  - Undo support

- [ ] Basic vulnerability detection (2h)
  - Buffer overflow patterns
  - Integer overflow detection
  - Format string vulnerabilities

**Week 6 (8 hours):**
- [ ] Local LLM optimization (4h)
  - Support for Ollama
  - Model selection UI
  - Performance tuning for large binaries

- [ ] Batch analysis mode (2h)
  - Select multiple functions
  - Queue AI processing
  - Progress tracking

- [ ] Documentation and testing (2h)
  - User guide
  - Example workflows
  - Unit tests

**Deliverables:**
- Complete GhidrAssist plugin
- MCP integration guide
- Example AI prompts library
- Release notes

**Impact:**
- First AI-integrated Ghidra plugin with MCP
- Unique differentiator vs competitors (Decyx, ReVA)
- Foundation for future ML features

---

### Week 7-9: GhidraSimilarity (20 hours)
**Roadmap:** Plugin Roadmap (TIER 1)
**ROI Score:** 90/100

#### Purpose
Machine learning-based function matching and binary similarity analysis

#### Implementation Plan

**Week 7 (8 hours):**
- [ ] Design ML feature extraction pipeline (2h)
  - Instruction n-grams
  - Control flow graph features
  - API call patterns
  - String references

- [ ] Implement feature extraction (4h)
  - PyGhidra integration
  - Feature normalization
  - Feature caching

- [ ] Build similarity scoring algorithm (2h)
  - Cosine similarity baseline
  - Weighted feature importance

**Week 8 (8 hours):**
- [ ] Train ML model for function detection (4h)
  - Collect training dataset (known libraries)
  - Train scikit-learn model
  - Validate accuracy (>85% target)

- [ ] Build cross-binary matching UI (3h)
  - Select two programs
  - Run matching algorithm
  - Display results table (confidence scores)

- [ ] Implement auto-labeling (1h)
  - Import function names from matches
  - Confidence threshold filtering

**Week 9 (4 hours):**
- [ ] Optional: RevEng.AI API integration (2h)
  - API key configuration
  - Query function signatures
  - Display results alongside local matches

- [ ] Integration with GhidraGraph (1h)
  - Visualize matched functions
  - Highlight differences

- [ ] Testing and documentation (1h)

**Deliverables:**
- GhidraSimilarity plugin
- ML model (pre-trained on common libraries)
- Integration with GhidraGraph visualization
- User guide with examples

**Impact:**
- Addresses stripped binary pain point
- ML/AI alignment with 2025 trends
- Potential for community-contributed models

---

### Week 10-11: GhidraGo (16 hours)
**Roadmap:** Plugin Roadmap (TIER 1)
**ROI Score:** 88/100

#### Purpose
Deep analysis of Golang binaries (malware trend)

#### Implementation Plan

**Week 10 (8 hours):**
- [ ] Research Go runtime structures (2h)
  - String table layout
  - Type information structures
  - Interface definitions

- [ ] Implement string table recovery (3h)
  - Locate string table in binary
  - Parse string entries
  - Apply to decompilation

- [ ] Function signature reconstruction (3h)
  - Extract parameter count
  - Identify return values
  - Apply type annotations

**Week 11 (8 hours):**
- [ ] Type information extraction (3h)
  - Parse Go type metadata
  - Recover struct definitions
  - Apply to Data Type Manager

- [ ] Interface analysis (2h)
  - Identify interface implementations
  - Method resolution

- [ ] Runtime structure detection (2h)
  - Goroutine structures
  - Channel operations
  - Defer/panic/recover patterns

- [ ] Testing and documentation (1h)

**Deliverables:**
- GhidraGo plugin
- Pre-configured analyzers for Go binaries
- Library of Go runtime signatures
- Example analysis workflows

**Impact:**
- Go malware analysis capability
- Addresses proven community demand
- Complements GhidraGraph for visualization

---

### Week 12: Integration & Polish (8 hours)

#### Tasks
- [ ] Cross-plugin integration testing (3h)
  - GhidraGraph + GhidraSimilarity
  - GhidraGraph + GhidraGo
  - GhidrAssist + GhidraSimilarity

- [ ] Unified documentation (2h)
  - Plugin suite overview
  - Installation guide
  - Workflow examples

- [ ] Community preparation (2h)
  - GitHub releases
  - Release announcements
  - Example projects

- [ ] Future roadmap planning (1h)

**Deliverables:**
- Catalytic Computing Plugin Suite v2.0
- Complete documentation
- GitHub releases
- Community announcement posts

---

## Resource Allocation

### Time Investment Summary

| Phase | Weeks | Hours | Focus |
|-------|-------|-------|-------|
| **Phase 1: Foundation** | 1-4 | 80-100 | Security + Infrastructure |
| **Phase 2: Innovation** | 5-12 | 120-150 | Ghidra Plugins (AI/ML) |
| **TOTAL** | 12 weeks | **200-250 hours** | Complete transformation |

### Weekly Commitment

**Phase 1 (Weeks 1-4):** 20-25 hours/week
**Phase 2 (Weeks 5-12):** 15-19 hours/week

**Sustainability:** ~3 hours/day on weekdays OR full weekends

---

### Cost Summary

| Category | Monthly Cost | Annual Cost | Notes |
|----------|--------------|-------------|-------|
| **Infrastructure** | $0 | $0 | 100% open-source stack |
| **CI/CD** | $0 | $0 | GitHub Actions (public repo) |
| **Monitoring** | $0 | $0 | Self-hosted Prometheus/Grafana |
| **Security** | $0 | $0 | Vault OSS, Trivy |
| **Optional: Managed Services** | $27 | $324 | Grafana Cloud + GitHub private |
| **TOTAL (Recommended)** | **$0/month** | **$0/year** | |

---

## Success Metrics

### Phase 1 Completion Criteria (Week 4)

**Security Framework:**
- [x] Load testing: 10,000 concurrent users (>95% success rate)
- [x] Performance: P95 latency < 500ms
- [x] Zero crashes under all failure scenarios
- [x] Production rating: 10/10 (upgraded from 9.2)

**Infrastructure:**
- [x] CI/CD: Automated deployment to all platforms
- [x] Monitoring: 5+ Grafana dashboards
- [x] Alerts: All critical alerts configured
- [x] Secrets: 100% in Vault (zero hardcoded)
- [x] Deployments: Canary strategy with auto-rollback

**Documentation:**
- [x] Production deployment guide
- [x] Incident response runbook
- [x] API documentation (Swagger UI)

---

### Phase 2 Completion Criteria (Week 12)

**Ghidra Plugins:**
- [x] GhidrAssist: 100% feature complete
- [x] GhidraSimilarity: ML-based matching operational
- [x] GhidraGo: Golang analysis fully functional
- [x] Test coverage: >90% for all plugins

**Integration:**
- [x] Plugins work together seamlessly
- [x] Unified documentation
- [x] GitHub releases with CI/CD

**Community:**
- [x] Release announcements published
- [x] Example projects created
- [x] Next roadmap defined

---

## Risk Mitigation

### Phase 1 Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Load testing reveals bottlenecks | Medium | High | Week 3 buffer for optimization |
| Vault migration breaks services | Low | High | Staging validation + rollback plan |
| CI/CD complexity delays delivery | Medium | Medium | Use existing workflows as templates |

### Phase 2 Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| ML model accuracy insufficient | Medium | Medium | Start with simple cosine similarity |
| Go binary format changes | Low | Medium | Use existing gotools as reference |
| Plugin compatibility issues | Low | High | Test with multiple Ghidra versions |

---

## Dependencies & Prerequisites

### Before Starting (Week 0)

**Infrastructure:**
- [x] Docker installed and running
- [x] Kubernetes cluster access (or Minikube)
- [x] GitHub account with Actions enabled
- [x] Docker Hub account (wo1ves)

**Development:**
- [x] Python 3.9+ environment
- [x] Ghidra 11.x installed
- [x] Java 17+ for plugin development

**Security:**
- [x] Redis running (for tests)
- [x] PostgreSQL (for SaaS tests)
- [x] Test environments configured

---

## Critical Path Analysis

### Blockers (Must Complete in Order)

```
Week 1: Load Testing
    ↓ (blocks)
Week 1: Performance Optimization
    ↓ (blocks)
Week 2: CI/CD Enhancement
    ↓ (enables)
Week 3: Vault Deployment
    ↓ (blocks)
Week 4: Production Validation
    ↓ (enables)
Week 5+: Plugin Development
```

**Critical Dependencies:**
1. Load testing must complete before performance optimization
2. Monitoring stack must deploy before Vault (need metrics)
3. CI/CD must work before production deployment
4. Production platform must stabilize before plugin development

---

## Parallel Work Opportunities

### Week 1 Parallel Tracks
- **Track A:** Load testing execution (Engineer 1)
- **Track B:** Monitoring stack setup (Engineer 2)

### Week 2 Parallel Tracks
- **Track A:** CI/CD workflows (Engineer 1)
- **Track B:** Observability (Loki, OpenCost) (Engineer 2)

### Phase 2 Parallel Tracks
- **Track A:** GhidrAssist completion (AI focus)
- **Track B:** GhidraSimilarity research (ML focus)

---

## Next Actions (Week 1 Kickoff)

### Monday (Day 1)
1. Set up load testing environment (Locust/K6)
2. Create test scenarios for 1,000 users
3. Execute initial load test
4. Review results and identify bottlenecks

### Tuesday (Day 2)
1. Execute 10,000 user load test
2. Analyze performance metrics
3. Document findings
4. Create optimization plan

### Wednesday (Day 3)
1. Deploy Prometheus to development
2. Configure service discovery
3. Verify metrics collection

### Thursday (Day 4)
1. Deploy Grafana
2. Create security dashboard
3. Configure data source

### Friday (Day 5)
1. Deploy Swagger UI
2. Configure health check monitoring
3. Document Week 1 results
4. Plan Week 2 tasks

---

## Measurement & Tracking

### Weekly Check-ins

**Every Friday:**
- Review completed tasks vs plan
- Update risk register
- Adjust next week's priorities
- Document lessons learned

**Metrics to Track:**
- Hours spent vs planned
- Tasks completed vs scheduled
- Blockers encountered
- Quality metrics (test coverage, performance)

### Deliverable Tracking

| Week | Planned Deliverables | Actual | Status |
|------|---------------------|--------|--------|
| 1 | Load test results, Monitoring stack | TBD | Pending |
| 2 | CI/CD workflows, Loki deployment | TBD | Pending |
| 3 | Vault deployment, Performance optimization | TBD | Pending |
| 4 | Canary deployments, Production validation | TBD | Pending |
| 5-6 | GhidrAssist complete | TBD | Pending |
| 7-9 | GhidraSimilarity | TBD | Pending |
| 10-11 | GhidraGo | TBD | Pending |
| 12 | Integration & polish | TBD | Pending |

---

## Expected Outcomes

### After Phase 1 (Week 4)

**Technical Capabilities:**
- ✅ Production-ready security framework (10/10 rating)
- ✅ Fully automated CI/CD pipeline
- ✅ Comprehensive monitoring and alerting
- ✅ Zero-downtime deployment capability
- ✅ Enterprise-grade secret management

**Operational Capabilities:**
- ✅ Deploy to production with one command
- ✅ Rollback in <2 minutes
- ✅ Monitor system health in real-time
- ✅ Respond to incidents with runbook
- ✅ Scale to 10,000+ concurrent users

---

### After Phase 2 (Week 12)

**Plugin Portfolio:**
- ✅ 8 total plugins (5 existing + 3 new)
- ✅ AI-integrated analysis (GhidrAssist)
- ✅ ML-based similarity matching (GhidraSimilarity)
- ✅ Golang binary analysis (GhidraGo)

**Market Position:**
- ✅ Leading open-source Ghidra plugin suite
- ✅ Unique AI/ML capabilities
- ✅ Proven at scale (via load testing)
- ✅ Enterprise-ready infrastructure

**Community Impact:**
- ✅ GitHub releases with CI/CD
- ✅ Complete documentation
- ✅ Example projects and tutorials
- ✅ Active community engagement

---

## Conclusion

This consolidated plan integrates three major roadmaps into a **cohesive 12-week strategy** that:

1. **Builds foundation first** (Weeks 1-4) → Production-ready platform
2. **Leverages stability for innovation** (Weeks 5-12) → Rapid plugin development
3. **Maximizes synergy** → CI/CD accelerates plugin iteration
4. **Minimizes risk** → Sequential completion of blockers

**Investment:** 200-250 hours over 12 weeks
**Cost:** $0/month (100% open-source stack)
**ROI:** Production-grade platform + 3 new AI/ML plugins

**Next Step:** Begin Week 1, Day 1 with load testing environment setup.

---

**Created:** October 7, 2025
**Status:** Ready to Execute
**Estimated Completion:** December 31, 2025
**Revision:** 1.0

---

*This plan consolidates: PLUGIN_ROADMAP_2025.md, PHASE_5_ROADMAP.md, and FRAMEWORK_CAPABILITY_ASSESSMENT.md into a single unified execution strategy.*
