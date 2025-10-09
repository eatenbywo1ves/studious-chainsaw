# Technical Debt Register

**Last Updated:** 2025-10-08
**Next Review:** 2025-10-15

This is your living technical debt tracker. Update this file as you fix items or discover new debt.

---

## 🔴 High Priority (Blocking Future Features)

### ❌ Database Engine Created Per-Request
- **Status:** 🔴 OPEN
- **Severity:** CRITICAL
- **Discovered:** 2025-10-08
- **Impact:** Production crash at ~50 concurrent users
- **Effort:** 2 hours
- **Files:**
  - `saas/api/subscription_api.py:79-108`
  - `saas/api/tenant_api.py`
  - `saas/auth/middleware.py`
- **Fix:** Create `saas/database/connection.py` with shared engine
- **Assigned To:**
- **Target Date:**
- **Completed:** ☐

---

### ❌ Logging Infrastructure Missing
- **Status:** 🔴 OPEN
- **Severity:** HIGH
- **Discovered:** 2025-10-08
- **Impact:** Cannot debug production issues
- **Effort:** 4 hours
- **Coverage:** Only 5/25 files (20%) have logging
- **Fix:** Add logging to all SaaS modules
- **Assigned To:**
- **Target Date:**
- **Completed:** ☐

---

## 🟡 Medium Priority (Quality Improvements)

### ⚠️ Configuration Duplication
- **Status:** 🟡 OPEN
- **Severity:** MEDIUM
- **Discovered:** 2025-10-08
- **Impact:** Inconsistent configuration, difficult updates
- **Effort:** 3 hours
- **Files:** 8 files independently load dotenv
- **Fix:** Create centralized `saas/config/settings.py`
- **Assigned To:**
- **Target Date:**
- **Completed:** ☐

---

### ⚠️ API Router Test Coverage
- **Status:** 🟡 OPEN
- **Severity:** MEDIUM
- **Discovered:** 2025-10-08
- **Impact:** Regressions not caught, difficult refactoring
- **Effort:** 6 hours
- **Coverage:** 0% for API routers
- **Fix:** Add unit tests for subscription_api, tenant_api, auth_api
- **Assigned To:**
- **Target Date:**
- **Completed:** ☐

---

## 🟢 Low Priority (Nice to Have)

### ℹ️ Active User Status Check
- **Status:** 🟢 OPEN
- **Severity:** LOW
- **Discovered:** 2025-10-08 (existing TODO)
- **Impact:** Cannot disable user accounts effectively
- **Effort:** 30 minutes
- **File:** `saas/auth/auth_dependencies.py:161`
- **Fix:** Add database query for user status
- **Assigned To:**
- **Target Date:**
- **Completed:** ☐

---

### ℹ️ Error Handling Standardization
- **Status:** 🟢 OPEN
- **Severity:** LOW
- **Discovered:** 2025-10-08
- **Impact:** Inconsistent error messages, difficult client integration
- **Effort:** 2 hours
- **Fix:** Create custom exception hierarchy
- **Assigned To:**
- **Target Date:**
- **Completed:** ☐

---

## ✅ Completed Items

_(Move items here when completed)_

---

## Debt Statistics

**Last Calculated:** 2025-10-08

| Priority | Count | Total Effort |
|----------|-------|--------------|
| 🔴 High | 2 | 6 hours |
| 🟡 Medium | 2 | 9 hours |
| 🟢 Low | 2 | 2.5 hours |
| **Total** | **6** | **17.5 hours** |

**Critical Path (Must fix before production):** 6 hours

---

## Maintenance Schedule

### Weekly (Every Sunday 9 PM)
- [ ] Review this register
- [ ] Fix 1-2 items from High Priority
- [ ] Add new items discovered during the week
- [ ] Update status of in-progress items

### Monthly (First Sunday)
- [ ] Calculate debt metrics
- [ ] Assess if debt is growing or shrinking
- [ ] Plan refactoring sprint if needed
- [ ] Archive completed items

---

## Adding New Debt Items

When you discover new technical debt, add it using this template:

```markdown
### ⚠️ [Brief Description]
- **Status:** 🔴/🟡/🟢 OPEN
- **Severity:** CRITICAL/HIGH/MEDIUM/LOW
- **Discovered:** YYYY-MM-DD
- **Impact:** [What happens if not fixed]
- **Effort:** [Estimated hours]
- **Files:** [Affected files]
- **Fix:** [Brief fix description]
- **Assigned To:** [Your name]
- **Target Date:** [When you plan to fix]
- **Completed:** ☐
```

---

## Severity Guidelines

**🔴 CRITICAL (High Priority)**
- Causes production outages
- Security vulnerabilities
- Data loss risks
- Fix within 1 week

**🟡 MEDIUM (Medium Priority)**
- Impacts performance or scalability
- Makes future changes difficult
- Increases bug risk
- Fix within 1 month

**🟢 LOW (Low Priority)**
- Code quality improvements
- Minor inconsistencies
- Nice-to-have features
- Fix when convenient

---

## Notes

- This register should be reviewed during every commit that adds technical debt
- When taking shortcuts for velocity, document them here
- Better to acknowledge debt than hide it
- Debt compounds - address high priority items quickly

---

**References:**
- [Technical Debt Analysis (Full Report)](./TECHNICAL_DEBT_ANALYSIS.md)
- [Quick Reference Card](./TECHNICAL_DEBT_QUICK_REFERENCE.md)
