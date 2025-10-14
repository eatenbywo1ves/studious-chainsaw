# Directory Cleanup - Quick Reference Card
**Fast lookup for execution**

---

## ONE-LINER SUMMARY
**18 root markdown files → 3 files + organized structure in 25 minutes**

---

## DECISION MATRIX

```
✅ Execute if:                      ❌ Skip if:
• Root is cluttered                • Root already clean
• Need better organization         • No time for cleanup
• Want professional structure      • Breaking changes unacceptable
• Can spare 25 minutes            • Team not ready for change
```

**Confidence: 9.5/10 | Risk: LOW | Time: 25 min**

---

## FILE DESTINATIONS (Cheat Sheet)

```
KEEP (3):
  README.md                                → Stay at root
  OPTIMAL_DEPLOYMENT_STRATEGY.md          → Rename to DEPLOYMENT_STRATEGY.md
  claude_health_report.md                  → Stay at root

ARCHIVE (5) → Archive/planning/2025-10/:
  DIRECTORY_REMEDIATION_PLAN.md
  SYSTEMATIC_DIRECTORY_DEPLOYMENT_PLAN.md
  STRATEGIC_PLAN_CONSOLIDATION_REPORT.md
  CONSOLIDATION_EXECUTIVE_SUMMARY.md
  DOCUMENT_OVERLAP_VISUALIZATION.md

GUIDES (7) → docs/guides/:
  EXECUTION_QUICK_START.md                 → execution-quick-start.md
  CONTEXT_QUICK_REFERENCE.md              → context-reference.md
  MCP_PRODUCTION_DEPLOYMENT_GUIDE.md      → mcp-deployment.md
  production_readiness_guide.md           → production-readiness.md
  REACTIVE_PROGRAMMING_COMPLETE_GUIDE.md  → reactive-programming.md
  LOG_MANAGEMENT_SETUP.md                 → log-management.md
  CATALYTIC_README.md                     → catalytic-computing.md

REPORTS (3) → docs/reports/:
  GPU_ACCELERATION_REPORT.md                              → gpu-acceleration.md
  NVIDIA_Container_Toolkit_Security_Research_Report.md   → nvidia-security-research.md
  CATALYTIC_COMPUTING_DOCUMENTATION.md                   → catalytic-computing-architecture.md
```

---

## EXECUTION (Copy-Paste)

### Full Command Sequence
```bash
# 1. Create structure
mkdir -p Archive/planning/2025-10 docs/guides docs/reports && \
touch Archive/.gitkeep docs/.gitkeep docs/guides/.gitkeep docs/reports/.gitkeep

# 2. Archive planning (5 files)
git mv DIRECTORY_REMEDIATION_PLAN.md Archive/planning/2025-10/ && \
git mv SYSTEMATIC_DIRECTORY_DEPLOYMENT_PLAN.md Archive/planning/2025-10/ && \
git mv STRATEGIC_PLAN_CONSOLIDATION_REPORT.md Archive/planning/2025-10/ && \
git mv CONSOLIDATION_EXECUTIVE_SUMMARY.md Archive/planning/2025-10/ && \
git mv DOCUMENT_OVERLAP_VISUALIZATION.md Archive/planning/2025-10/

# 3. Organize guides (7 files)
git mv EXECUTION_QUICK_START.md docs/guides/execution-quick-start.md && \
git mv CONTEXT_QUICK_REFERENCE.md docs/guides/context-reference.md && \
git mv MCP_PRODUCTION_DEPLOYMENT_GUIDE.md docs/guides/mcp-deployment.md && \
git mv production_readiness_guide.md docs/guides/production-readiness.md && \
git mv REACTIVE_PROGRAMMING_COMPLETE_GUIDE.md docs/guides/reactive-programming.md && \
git mv LOG_MANAGEMENT_SETUP.md docs/guides/log-management.md && \
git mv CATALYTIC_README.md docs/guides/catalytic-computing.md

# 4. Organize reports (3 files)
git mv GPU_ACCELERATION_REPORT.md docs/reports/gpu-acceleration.md && \
git mv NVIDIA_Container_Toolkit_Security_Research_Report.md docs/reports/nvidia-security-research.md && \
git mv CATALYTIC_COMPUTING_DOCUMENTATION.md docs/reports/catalytic-computing-architecture.md

# 5. Rename strategy
git mv OPTIMAL_DEPLOYMENT_STRATEGY.md DEPLOYMENT_STRATEGY.md

# 6. Create indexes (see DIRECTORY_CLEANUP_PLAN.md for content)
# [Create Archive/planning/2025-10/README.md]
# [Create docs/README.md]

# 7. Stage and commit
git add Archive/.gitkeep docs/.gitkeep docs/guides/.gitkeep docs/reports/.gitkeep && \
git add Archive/planning/2025-10/README.md docs/README.md && \
git commit -m "chore: consolidate and organize root directory documentation

Reorganize 18 root markdown files into clean structure:
- Keep 3 essential files at root
- Archive 5 planning docs to Archive/planning/2025-10/
- Move 7 guides to docs/guides/
- Move 3 reports to docs/reports/

Root files: 18 → 3 (83% reduction)

Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# 8. Verify
bash verify_cleanup.sh
```

---

## ROLLBACK (Emergency)

```bash
# Option 1: Undo commit, keep changes
git reset --soft HEAD~1

# Option 2: Undo everything
git reset --hard HEAD~1

# Option 3: Create reverse commit
git revert HEAD
```

**Recovery: < 5 minutes**

---

## VERIFICATION (Quick Check)

```bash
# Should show 3 files
ls -1 *.md | wc -l

# Should show 7 files
ls -1 docs/guides/*.md | wc -l

# Should show 3 files
ls -1 docs/reports/*.md | wc -l

# Should show 6 files (5 + README)
ls -1 Archive/planning/2025-10/*.md | wc -l

# Run comprehensive verification
bash verify_cleanup.sh
```

---

## CHECKLIST (Print & Use)

```
PRE-EXECUTION:
[ ] Branch clean (git status)
[ ] Read DIRECTORY_CLEANUP_PLAN.md
[ ] Understand git mv preserves history
[ ] Ready to execute

EXECUTION:
[ ] Create directories
[ ] Create index files
[ ] Archive 5 planning docs
[ ] Move 7 guides
[ ] Move 3 reports
[ ] Rename strategy file
[ ] Stage new files
[ ] Commit changes

POST-EXECUTION:
[ ] Run verify_cleanup.sh
[ ] All checks pass
[ ] Update README.md
[ ] Continue with deployment
```

---

## METRICS (Target State)

```
Root Directory:
  Before: 18 files
  After:   3 files
  Change: -83% ✓

Organization:
  docs/guides/:   7 files
  docs/reports/:  3 files
  Archive/:       5 files
  Total organized: 15 files ✓

Git History:
  Preserved: 100% ✓
  Rollback:  < 5 min ✓
```

---

## DOCUMENTS HIERARCHY

```
Quick Decision:
  → CLEANUP_EXECUTIVE_SUMMARY.md (this first!)

Visual Overview:
  → CLEANUP_VISUAL_SUMMARY.md (diagrams & charts)

Detailed Execution:
  → DIRECTORY_CLEANUP_PLAN.md (step-by-step)

Fast Reference:
  → CLEANUP_QUICK_REFERENCE.md (you are here)

Verification:
  → verify_cleanup.sh (run after execution)
```

---

## SUPPORT COMMANDS

```bash
# Check git status
git status

# See what will be moved
git diff --staged

# Preview commit message
git commit --dry-run

# Count root markdown files
ls -1 *.md 2>/dev/null | wc -l

# List all markdown files
find . -name "*.md" -type f

# Check file exists
test -f "path/to/file.md" && echo "exists" || echo "missing"
```

---

## COMMON ISSUES

```
Issue: "Directory not empty"
Fix: Use git mv, not mv

Issue: "File not found"
Fix: Verify file name exactly (case-sensitive)

Issue: "Commit failed"
Fix: Run git status, stage all files

Issue: "Lost file"
Fix: Check git log --follow <filename>

Issue: "Want to undo"
Fix: git reset --hard HEAD~1
```

---

## CONTACT INFO

```
Questions about:
  Technical details → DIRECTORY_CLEANUP_PLAN.md
  Visual diagrams   → CLEANUP_VISUAL_SUMMARY.md
  Decision factors  → CLEANUP_EXECUTIVE_SUMMARY.md
  Quick commands    → CLEANUP_QUICK_REFERENCE.md (here)
```

---

## NEXT ACTIONS

```
After Cleanup Complete:
1. Update README.md with new structure
2. Update internal links (if any broken)
3. Continue DEPLOYMENT_STRATEGY.md execution
4. Celebrate clean repository! 🎉
```

---

**Status**: ✅ READY
**Time**: 25 minutes
**Risk**: LOW
**Rollback**: < 5 minutes

**Print this card for quick reference during execution!**
