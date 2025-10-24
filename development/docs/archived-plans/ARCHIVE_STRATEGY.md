# Project Archive Strategy

**Last Updated:** 2025-10-14
**Purpose:** Define what to do with non-core projects during the freeze

---

## 🗄️ Archive Tiers

### Tier 1: Maintenance Mode (Accessible, Not Active)
**Policy:** Keep in workspace, critical bugs only, no feature development

| Project | Location | Reason | Unarchive If... |
|---------|----------|--------|-----------------|
| Reactive Webhooks | `services/webhooks/reactive/` | Functional but not core focus | Becomes dependency of SaaS |
| Dashboard Framework | `projects/active/shared/` | Integrated into SaaS | SaaS needs dashboard features |
| Monitoring Stack | `monitoring/` | Operational, just observe | Performance issues arise |
| GhidraCtrlP | `GhidraCtrlP/` | Stable, works | User requests features |
| Ghidraaas | `Ghidraaas/` | Stable | Becomes service dependency |
| GhidraGraph | `GhidraGraph/` | Stable | Visualization needs arise |
| Ghidrathon | `Ghidrathon/` | Python bridge works | Need Python integration |
| Security Hardening | `security/` | Continuous, not project | Security audit needed |

### Tier 2: Deep Archive (Move to Archive Directory)
**Policy:** Move to `archives/2025/`, not deleted, just out of sight

| Project | Current Location | Move To | Size | Last Modified |
|---------|------------------|---------|------|---------------|
| Career Materials | `career/` | `archives/2025/career/` | ~500KB | Oct 10 |
| Demos | `demos/` | `archives/2025/demos/` | ? | ? |
| Pitch Materials | `pitch/` | `archives/2025/pitch/` | ? | ? |
| Refactoring Docs | `refactoring/` | `archives/2025/refactoring/` | ? | ? |
| Old Backups | `backups/` | `archives/2025/backups/` | Large | Various |

**Commands:**
```bash
cd development
mkdir -p archives/2025
mv career archives/2025/
mv demos archives/2025/
mv pitch archives/2025/
mv refactoring archives/2025/
git add archives/
git commit -m "chore: archive non-core projects to reduce cognitive load"
```

### Tier 3: Consider Deletion (If Untouched After Freeze)
**Policy:** If not accessed for 2 weeks, permanently delete or move to external storage

| Project | Reason | Check On | Decision |
|---------|--------|----------|----------|
| `esp32_flash_loader/` | Single-purpose tool | 2025-10-28 | Delete if unused |
| `HyperDbg-Scripts/` | Third-party scripts | 2025-10-28 | Delete if unused |
| `.backup_links_20251010/` | Temporary backup | Immediate | Delete now |
| `ghidrago_java_backup/` | Old backup | 2025-10-28 | Delete if GhidraGo stable |

**Safe Deletion Commands:**
```bash
# Create safety bundle first
cd development
git bundle create safety-backup-2025-10-14.bundle --all

# Then delete
rm -rf .backup_links_20251010/
git add -A
git commit -m "chore: remove temporary backup directory"
```

---

## 📦 Special Case: KA Lattice / Catalytic Computing

**Status:** Research/Experimental
**Location:** `apps/catalytic/`, `ka_lattice_state/`, etc.
**Decision:** Maintenance mode

**Rationale:**
- Interesting research but not production-ready
- Consumes cognitive load without clear ROI
- Can revisit after core projects ship

**Action:**
- No new development for 2 weeks
- If inspiration strikes, capture in GitHub Issues only
- After freeze: evaluate if this becomes Core Project #5

---

## 🎯 Archive Execution Plan

### Phase 1: Immediate (Today)
```bash
# 1. Delete obvious temporary files
cd development
rm -rf .backup_links_20251010/

# 2. Add archive patterns to gitignore
echo "archives/2025/" >> .gitignore

# 3. Commit the freeze infrastructure
git add CORE_PROJECTS.md FREEZE_QUICK_REFERENCE.md ARCHIVE_STRATEGY.md
git add .gitignore .github/hooks/
git commit -m "feat: implement documentation freeze and project consolidation"
```

### Phase 2: This Week
```bash
# Move Tier 2 archives
mkdir -p archives/2025
mv career demos pitch refactoring backups archives/2025/
git add archives/ career demos pitch refactoring backups
git commit -m "chore: archive non-core projects (Tier 2)"
```

### Phase 3: End of Freeze (2025-10-28)
```bash
# Review Tier 3 deletions
# For each untouched project, run:
git bundle create pre-delete-backup-PROJECT.bundle main
rm -rf PROJECT/
git add -A
git commit -m "chore: delete unused PROJECT after 2-week evaluation"
```

---

## 📊 Cognitive Load Reduction

**Before Freeze:**
- 65+ directories in development/
- 10+ active projects
- ~40% commits are organizational

**After Archive:**
- ~20 visible directories (archives hidden)
- 4 core projects
- Target: 75% feature commits

**Mental Model:**
```
development/
├── ml-sectest-framework/    ← Core #1
├── saas/                     ← Core #2
├── GhidraGo/                 ← Core #3
├── projects/
│   └── platform/
│       └── mcp-gateway/      ← Core #4
└── [everything else is background noise]
```

---

## 🚨 Emergency Unarchive

If you need to work on an archived project:

```bash
# 1. Ask yourself: Is this REALLY urgent?
# 2. If yes, move it back
mv archives/2025/PROJECT ./
git add PROJECT archives/2025/
git commit -m "unarchive: PROJECT needed for [specific reason]"

# 3. Update CORE_PROJECTS.md if it becomes core
# 4. Track why you broke the freeze (learning opportunity)
```

---

## 🎓 Philosophy

**The Goal:** Reduce context switching and decision fatigue

**The Rule:** You can only actively develop on projects that fit in your head simultaneously

**The Reality:** Most humans can deeply focus on 3-4 complex projects at once

**The Benefit:** Shipping finished products instead of maintaining 10 half-done projects

---

## 📈 Success Metrics

Track every Friday:

```markdown
### Week of 2025-10-14
- Archived projects: ___
- Deleted projects: ___
- Active projects: 4 (target)
- Cognitive load: Low / Medium / High
- Did archiving help? Yes / No / Unsure

### Week of 2025-10-21
- ...
```

---

**Remember:** Archiving is not failure. It's strategic focus.

You can't ship everything. Ship the important things.
