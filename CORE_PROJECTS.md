# Core Projects - Active Development Focus

**Documentation Freeze Active:** 2025-10-14 through 2025-10-28 (2 weeks)
**Last Updated:** 2025-10-14

---

## 🎯 THE 4 CORE PROJECTS

These are the ONLY projects receiving active development. All other projects are in maintenance mode or archived.

### 1. **ML Security Testing Framework** 🛡️
**Path:** `development/ml-sectest-framework/`
**Status:** Production Ready (v1.0.0)
**Priority:** HIGH
**Owner:** Primary development focus

**Mission:** Agentic AI-powered security testing framework with game-theoretic attack coordination.

**Key Components:**
- Edward Teller Agent (fusion attack chains)
- Agent Coordinator (Nash equilibrium strategy)
- 6 specialized security agents
- 105 tests @ 97% pass rate

**Current Sprint Goals:**
- [ ] Fix 3 failing tests (CORS, agent loading, scan method)
- [ ] Deploy to production environment
- [ ] Create first real-world security scan
- [ ] Publish v1.0.0 release to GitHub

**Docs Location:** `development/ml-sectest-framework/README.md` (ONE file only)

**No New Docs Allowed:** Use GitHub Issues for planning, not markdown files.

---

### 2. **SaaS Multi-Tenant Platform** 💼
**Path:** `development/saas/`
**Status:** Production Ready - Auth Complete
**Priority:** HIGH
**Owner:** Primary development focus

**Mission:** Production-grade SaaS platform with Stripe billing, JWT auth, and Redis-backed distributed systems.

**Key Components:**
- Stripe payment integration (webhooks, subscriptions, portal)
- JWT authentication (99.89% @ 1K users, 99.29% @ 10K users)
- Redis connection pooling (678K+ commands processed)
- RBAC with dashboard permissions
- PostgreSQL + SQLite compatibility

**Current Sprint Goals:**
- [ ] Build first customer-facing feature (define what this is)
- [ ] Add subscription tier enforcement
- [ ] Implement usage metering/quotas
- [ ] Create admin dashboard

**Docs Location:** `development/saas/README.md` (ONE file only)

**No New Docs Allowed:** Architecture decisions go in code comments or ADRs (if absolutely necessary).

---

### 3. **GhidraGo - Binary Analysis** 🔍
**Path:** `development/GhidraGo/`
**Status:** Released (v2.2.0)
**Priority:** MEDIUM
**Owner:** Secondary development focus

**Mission:** Production Golang binary analyzer with intelligent caching and Ghidra 11.4.2 API integration.

**Key Components:**
- Auto-Analyzer integration
- Intelligent caching system
- GitHub release automation
- GhidraCtrlP fuzzy search enhancement

**Current Sprint Goals:**
- [ ] User feedback collection from v2.2.0
- [ ] Bug fixes only (no new features for 2 weeks)
- [ ] Performance benchmarking
- [ ] Consider next version roadmap

**Docs Location:** `development/GhidraGo/README.md` (ONE file only)

**No New Docs Allowed:** Release notes go in GitHub Releases, not separate files.

---

### 4. **MCP Platform Infrastructure** 🏗️
**Path:** `projects/platform/mcp-gateway/`
**Status:** Production Ready
**Priority:** MEDIUM
**Owner:** Infrastructure support

**Mission:** Model Context Protocol gateway for orchestrating multiple MCP servers with production-ready persistence.

**Key Components:**
- Registry persistence layer (JSON backend)
- Router with stdio limitation handling
- Health monitoring integration
- Multi-server orchestration

**Current Sprint Goals:**
- [ ] Stability testing in production
- [ ] Performance profiling under load
- [ ] Error handling improvements
- [ ] Monitoring dashboard integration

**Docs Location:** `projects/platform/mcp-gateway/README.md` (ONE file only)

**No New Docs Allowed:** API docs in code via JSDoc/TSDoc only.

---

## 🗄️ ARCHIVED PROJECTS (Maintenance Mode Only)

These projects receive **critical bug fixes only**. No feature development for 2 weeks minimum.

### In Maintenance Mode:
- **Reactive Webhooks** - Functional but not core focus
- **Dashboard Framework** - Integrated into SaaS, no standalone work
- **Monitoring & Alerting** - Operational, observe only
- **Ghidra Extensions** (GhidraCtrlP, Ghidraaas, etc.) - Stable, maintenance only
- **Security Hardening** - Continuous process, not active project
- **KA Lattice / Catalytic Computing** - Research phase, paused

### Fully Archived:
- **Career materials** - Moved to separate repo or offline
- **Demos** - Reference only
- **Pitch materials** - Not active development

---

## 📜 DOCUMENTATION FREEZE RULES

**Effective:** 2025-10-14 to 2025-10-28 (2 weeks minimum)

### ❌ FORBIDDEN DURING FREEZE

1. **No new markdown files** in any root directory
2. **No new "planning" documents** (use GitHub Issues)
3. **No new "status" documents** (use GitHub Project boards)
4. **No "analysis" or "report" files** (use GitHub Discussions)
5. **No "roadmap" files** (use GitHub Milestones)
6. **No "cleanup" or "consolidation" documents**
7. **No documentation about documentation**

### ✅ ALLOWED DURING FREEZE

1. **Update existing README.md** files (limit: 1 per project)
2. **Code comments** and **inline documentation**
3. **API documentation** via docstrings/JSDoc/TSDoc
4. **CHANGELOG.md** updates (version history only)
5. **GitHub Issues, PRs, Discussions** (unlimited)
6. **Critical security documentation** (if unavoidable)

### 🔒 ENFORCEMENT

Pre-commit hooks will **block**:
- New `.md` files in root directories
- Files matching `*PLAN*.md`, `*STATUS*.md`, `*ANALYSIS*.md`, `*ROADMAP*.md`
- Files matching `*CLEANUP*.md`, `*CONSOLIDATION*.md`, `*ORGANIZATION*.md`

---

## 📊 SUCCESS METRICS

Track weekly during freeze:

### Velocity Metrics:
- **Feature commits** vs **doc commits** ratio (target: 4:1)
- **Tests added** (target: +10 per week)
- **GitHub Issues closed** (target: +5 per week)
- **Lines of production code** (measure growth)

### Anti-Metrics (these should DECREASE):
- Untracked `.md` files in root (target: 0)
- "Planning" commits (target: 0)
- Context switches between projects (target: max 2 per day)

---

## 🎯 FOCUS DISCIPLINE

### Daily Rule:
- **Morning:** Pick ONE core project
- **Work:** Stay in that project for minimum 4 hours
- **Afternoon:** Can switch to second core project if needed
- **No context switching** to archived projects except critical bugs

### Weekly Rule:
- **Monday:** Review core project progress
- **Friday:** Update this file with sprint progress only (no new files!)
- **Track:** How many times you broke the documentation freeze

---

## 🚀 POST-FREEZE PLAN (After 2025-10-28)

After the freeze, evaluate:

1. **Did velocity improve?** Measure feature commits vs. doc commits
2. **Which core projects shipped?** Actual releases, not plans
3. **What archives can be deleted?** Remove permanently if untouched
4. **Extend freeze or relax?** Based on results

**Rule:** Can only add a 5th core project if you ship v1.0 of an existing one.

---

## 📝 CHANGE LOG

- **2025-10-14:** Created core projects definition, activated documentation freeze
