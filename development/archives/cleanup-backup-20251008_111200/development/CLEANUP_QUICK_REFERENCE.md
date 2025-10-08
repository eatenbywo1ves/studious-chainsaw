# Documentation Cleanup - Quick Reference Card

**Full Plan**: See [DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md](DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md)

---

## ONE-COMMAND EXECUTION

```powershell
# Automated execution (with prompts)
.\scripts\execute-documentation-cleanup.ps1

# Fully automated (no prompts)
.\scripts\execute-documentation-cleanup.ps1 -AutoApprove

# Dry run (see what would happen)
.\scripts\execute-documentation-cleanup.ps1 -DryRun
```

---

## MANUAL EXECUTION

### Step 1: Create Backup (5 min)
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "C:\Users\Corbin\development\archives\cleanup-backup-$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force

# Backup all non-archived .md files
Get-ChildItem -Path "C:\Users\Corbin" -Filter "*.md" -File |
    Copy-Item -Destination "$backupDir\home" -Force
```

### Step 2: Phase 1 - Delete Duplicates (30 min)
```powershell
# See DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md Section: Phase 1
# Deletes 85 duplicate/superseded files
# Commit: git commit -m "docs: Phase 1 cleanup"
```

### Step 3: Phase 2 - Archive Historical (20 min)
```powershell
# See DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md Section: Phase 2
# Archives 30 historical reports
# Commit: git commit -m "docs: Phase 2 archive"
```

### Step 4: Phase 3 - Consolidate (45 min)
```powershell
# MANUAL STEP: Merge content from multiple files into master guides
# See Phase 3 for detailed merge instructions
# Commit: git commit -m "docs: Phase 3 consolidation"
```

### Step 5: Phase 4 - Restructure (25 min)
```powershell
# See DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md Section: Phase 4
# Creates final directory structure
# Commit: git commit -m "docs: Phase 4 restructure"
```

### Step 6: Validate
```powershell
.\scripts\validate-documentation-cleanup.ps1 -Verbose
```

---

## QUICK STATS

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| **Total Files** | 237 | 120 | **-49%** |
| **Home Directory** | 25 | 10 | **-60%** |
| **Development Root** | 128 | 25 | **-80%** |
| **Duplicates** | 85 | 0 | **-100%** |

---

## FILES AFFECTED BY PHASE

### Phase 1: Safe Deletions (85 files)
- BMAD duplicates: 6 files
- Execution plans: 6 files
- Deployment status: 9 files
- Phase completions: 20 files
- Redis duplicates: 5 files
- GPU duplicates: 5 files
- Security duplicates: 11 files
- Docs duplicates: 3 files
- Security deployment: 5 files

### Phase 2: Archive (30 files)
- Weekly reports → `archives/weekly-reports/`
- Session summaries → `archives/session-summaries/`
- Phase completions → `archives/phase-completions/`
- Historical plans → `archives/historical-plans/`

### Phase 3: Consolidation (40→10 files)
**Master Guides Created**:
- BMAD_MASTER_GUIDE.md
- DEPLOYMENT_STATUS.md
- REDIS_PRODUCTION_GUIDE.md
- GPU_ACCELERATION_GUIDE.md
- SECURITY_MASTER_GUIDE.md
- TESTING_GUIDE.md
- MCP_PRODUCTION_GUIDE.md
- MONITORING_OPERATIONS_GUIDE.md

### Phase 4: Restructure
**New Directory Structure**:
```
docs/
├── guides/          (Master guides)
├── api/             (API documentation)
├── deployment/      (Deployment guides)
├── monitoring/      (Monitoring docs)
├── security/        (Security docs)
├── walkthroughs/    (Component walkthroughs)
└── README.md        (Documentation index)
```

---

## SAFETY MECHANISMS

✅ **Full backup before any deletion**
✅ **Git commits after each phase**
✅ **Archive instead of delete (Phase 2)**
✅ **Validation script checks all changes**
✅ **Rollback procedures documented**

---

## EMERGENCY ROLLBACK

```powershell
# Restore from backup
$backupDir = Get-ChildItem "C:\Users\Corbin\development\archives" |
    Where-Object { $_.Name -match "cleanup-backup-" } |
    Sort-Object CreationTime -Descending | Select-Object -First 1

Copy-Item "$($backupDir.FullName)\*" -Destination "C:\Users\Corbin" -Recurse -Force

# Or git revert
git log --oneline -10
git revert [commit-hash]
```

---

## POST-CLEANUP MAINTENANCE

### Monthly Review
```powershell
# Check for new duplicates
.\scripts\maintain-docs.ps1 -CheckDuplicates

# Update timestamps
.\scripts\maintain-docs.ps1 -UpdateTimestamps

# Validate links
.\scripts\maintain-docs.ps1 -ValidateLinks
```

---

## EXPECTED TIMELINE

| Phase | Duration | Automation |
|-------|----------|------------|
| Backup | 5 min | 100% |
| Phase 1 | 30 min | 100% |
| Phase 2 | 20 min | 100% |
| Phase 3 | 45 min | 30% (manual merging) |
| Phase 4 | 25 min | 90% |
| Validation | 10 min | 100% |
| **Total** | **2h 15min** | **80% automated** |

---

## KEY FILES TO PRESERVE

These files will **NOT** be deleted:
- ✅ README.md (all instances)
- ✅ QUICK_START_GUIDE.md
- ✅ PHASE_5_ROADMAP.md
- ✅ PLUGIN_ROADMAP_2025.md
- ✅ CATALYTIC_COMPUTING_DOCUMENTATION.md
- ✅ REACTIVE_PROGRAMMING_COMPLETE_GUIDE.md
- ✅ WIZ_ZERODAY_CLOUD_2025_DEFENSE_STRATEGY.md
- ✅ All current deployment guides
- ✅ All GhidraGo release notes

---

## VALIDATION CHECKLIST

After cleanup, verify:
- [ ] File count reduced to ~120 files
- [ ] All archives created and populated
- [ ] Master guides exist in `docs/guides/`
- [ ] Documentation index at `docs/README.md`
- [ ] Git history clean with descriptive commits
- [ ] Backup directory exists
- [ ] No essential files deleted
- [ ] Validation script passes all tests

---

## GETTING HELP

**Full execution plan**: `DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md`
**Validation script**: `scripts/validate-documentation-cleanup.ps1`
**Maintenance script**: `scripts/maintain-docs.ps1`

**Questions?**
1. Review the full execution plan for detailed procedures
2. Check validation output for specific issues
3. Consult git history for what was changed

---

**Created**: 2025-10-08
**Last Updated**: 2025-10-08
**Status**: Ready for execution
