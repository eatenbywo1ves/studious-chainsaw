# 🚀 Systematic Directory Reorganization - Deployment Plan

**Created**: October 10, 2025
**Status**: ✅ Phase 0 Complete | 🟡 Ready for Phase 1A
**Est. Total Time**: 8-12 hours (spread over 2-3 days)
**Safety Checkpoint**: Commit `90adb26` - "checkpoint: before directory reorganization Phase 2"

---

## 🎯 Mission Objective

Execute systematic reorganization of C:\Users\Corbin\ directory structure to achieve:
- **Root Python files**: 12 → 0 (100% cleanup)
- **Root config files**: 4 → 0 (100% cleanup)
- **Organization score**: 6.5/10 → 9.5/10 (+46% improvement)
- **Top-level directories**: 58 → ~25 (57% reduction)

---

## 📊 Pre-Flight Status Report

### ✅ Phase 0: Pre-Flight Checks COMPLETE

**Git Status**:
- Branch: `main`
- Last commit: `90adb26` (safety checkpoint)
- Modified submodules: 5 (PRIMS, RepoMapper, desktop-notify, ghidra, tldraw-demo)
- Untracked: Tools/plugins/ghidra/GhidraEmu, development/.backup_links_20251010/

**Confirmed Files for Reorganization**:

**Python Files (12)**:
- production_api_server.py
- setup.py
- start_reactive_migration.py
- test_webhook_manager_reactive.py
- webhook_advanced_operators.py
- webhook_hot_cold_observables.py
- webhook_integrations.py
- webhook_manager.py
- webhook_manager_reactive.py
- webhook_monitoring.py
- webhook_reactive_flowchart.py
- webhook_router.py

**Config Files (4 + 1 archive)**:
- claude_optimization.json
- context_optimization_config.json
- ghidra_claude_config.json
- refactoring_data.json (39MB - for archival)
- catalytic-computing-production-v1.0.0.tar.gz (for archival)

**Empty Directories (2)**:
- tests/ (empty - confirmed)
- docker/ (empty - confirmed)

**Project Directories (6)**:
- catalytic-computing-production/ (exists)
- catalytic-lattice-k8s-agents/ (exists)
- ghidra-claude/ (exists)
- shared/ (exists)
- cosmos-viz/ (to verify)
- go-deployment-demo/ (to verify)

---

## 🛡️ Safety Protocols

### **Rollback Strategy**
```bash
# If anything goes wrong, rollback to checkpoint:
git reset --hard 90adb26
git clean -fd  # Remove untracked files if needed
```

### **Phase Checkpoints**
After each phase, create checkpoint commit:
```bash
git add -A
git commit -m "checkpoint: Phase [X] complete - [description]"
```

### **Verification After Each Move**
1. ✅ Verify file exists at new location
2. ✅ Verify file removed from old location
3. ✅ Git status shows move (not delete + add)
4. ✅ Run basic import/syntax checks if applicable

---

## 📋 PHASE 1A: Critical Fixes & Quick Wins

**Duration**: 1 hour
**Risk Level**: 🟢 Low
**Estimated Completion**: Day 1, Session 1

### **Task 1.1: Fix KA Lattice Numpy Bug** 🔴 PRODUCTION CRITICAL
**File**: `development/archives/old-logs/ka_lattice_production.log` (indicates issue in production_cycle.py)

**Agent Strategy**: Use general-purpose agent to locate exact file and add missing import

```bash
# Expected fix location:
# Find file containing 'production_cycle' with numpy usage
# Add: import numpy as np
```

**Success Criteria**:
- [ ] Import added to correct file
- [ ] File syntax validated
- [ ] Commit created

**Time**: 30 minutes

---

### **Task 1.2: Remove Empty Directories**
**Targets**: tests/, docker/

```bash
# Verify empty first
ls -la tests/
ls -la docker/

# Remove with git
git rm -r tests/
git rm -r docker/

# Verify removal
git status --short
```

**Agent Strategy**: Direct execution, no agent needed (simple)

**Success Criteria**:
- [ ] tests/ removed from git
- [ ] docker/ removed from git
- [ ] Git status clean

**Time**: 10 minutes

---

### **Task 1.3: Archive Large Files**
**Targets**: refactoring_data.json (39MB), catalytic-computing-production-v1.0.0.tar.gz

```bash
# Create archive directory if doesn't exist
mkdir -p Archive/analysis
mkdir -p Archive/releases

# Move files
git mv refactoring_data.json Archive/analysis/
git mv catalytic-computing-production-v1.0.0.tar.gz Archive/releases/

# Verify
git status --short
```

**Agent Strategy**: Direct execution

**Success Criteria**:
- [ ] refactoring_data.json in Archive/analysis/
- [ ] tar.gz in Archive/releases/
- [ ] Git shows moves, not deletions

**Time**: 10 minutes

---

### **Task 1.4: Phase 1A Checkpoint**
```bash
git commit -m "phase: 1A complete - critical fixes and quick wins

✅ Fixed KA Lattice numpy production bug
✅ Removed empty directories (tests/, docker/)
✅ Archived large files (39MB JSON, production tar.gz)

Impact:
- Root directory: -2 directories, -2 large files
- Production: KA Lattice warmup issue resolved

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Time**: 10 minutes

**Phase 1A Total**: ~1 hour

---

## 📋 PHASE 1B: Root-Level Code Organization

**Duration**: 2-3 hours
**Risk Level**: 🟡 Medium
**Estimated Completion**: Day 1, Session 2

### **Task 1B.1: Create Target Directory Structure**

**Agent Strategy**: Use general-purpose agent to verify and create structure

```bash
# Create new directories in development/
mkdir -p development/services/webhooks/reactive
mkdir -p development/config/claude
mkdir -p development/config/ghidra
mkdir -p development/config/data
mkdir -p development/apps/api
mkdir -p development/services/mcp

# Verify structure
tree development/ -L 3
```

**Success Criteria**:
- [ ] All target directories created
- [ ] Structure matches plan
- [ ] No git changes yet (directories will be added with files)

**Time**: 15 minutes

---

### **Task 1B.2: Move Webhook System Files (12 files)**

**Agent Strategy**: Use agent to verify all webhook imports/cross-references BEFORE moving

**Step 1: Discovery Agent** 🔍
```
Agent Task: Search entire codebase for:
1. Files importing any webhook_* modules
2. Files referencing webhook paths
3. Any hardcoded paths to webhook files

Return: List of all files that will need updates after move
```

**Step 2: Execute Moves**
```bash
# Move all webhook files
git mv webhook_advanced_operators.py development/services/webhooks/reactive/
git mv webhook_hot_cold_observables.py development/services/webhooks/reactive/
git mv webhook_integrations.py development/services/webhooks/reactive/
git mv webhook_manager.py development/services/webhooks/reactive/
git mv webhook_manager_reactive.py development/services/webhooks/reactive/
git mv webhook_monitoring.py development/services/webhooks/reactive/
git mv webhook_reactive_flowchart.py development/services/webhooks/reactive/
git mv webhook_router.py development/services/webhooks/reactive/
git mv start_reactive_migration.py development/services/webhooks/reactive/
git mv test_webhook_manager_reactive.py development/services/webhooks/reactive/

# Verify moves
git status --short
ls -la development/services/webhooks/reactive/
```

**Step 3: Update References Agent** 📝
```
Agent Task: Update all files identified in Step 1:
1. Update import statements (from webhook_* to from development.services.webhooks.reactive.webhook_*)
2. Update any path references
3. Verify syntax in modified files

Return: List of files updated with validation results
```

**Success Criteria**:
- [ ] All 10 webhook files moved
- [ ] All import references updated
- [ ] Python syntax validated
- [ ] Test file can be imported without errors

**Time**: 45 minutes

---

### **Task 1B.3: Move Config Files (4 files)**

**Agent Strategy**: Use agent to find references to these config files

**Step 1: Discovery Agent** 🔍
```
Agent Task: Search for references to:
- claude_optimization.json
- context_optimization_config.json
- ghidra_claude_config.json

Return: All files that load/reference these configs
```

**Step 2: Execute Moves**
```bash
# Move config files
git mv claude_optimization.json development/config/claude/
git mv context_optimization_config.json development/config/claude/
git mv ghidra_claude_config.json development/config/ghidra/

# Verify
git status --short
```

**Step 3: Update References** 📝
```bash
# Use agent to update all config path references
# OR create symlinks temporarily for compatibility

# Option A: Update paths in code
# Agent updates all references from "./claude_optimization.json"
# to "development/config/claude/claude_optimization.json"

# Option B: Temporary symlinks (safer short-term)
# ln -s development/config/claude/claude_optimization.json claude_optimization.json
```

**Success Criteria**:
- [ ] Config files moved
- [ ] All references updated OR symlinks created
- [ ] No broken config loads

**Time**: 30 minutes

---

### **Task 1B.4: Move API Server & MCP Monitor**

```bash
# Move API server
git mv production_api_server.py development/apps/api/

# Move MCP monitor
git mv mcp-health-monitor.js development/services/mcp/

# Move setup.py (if it's project-specific, otherwise keep at root)
# Need to determine if this is workspace setup or project setup
# Agent: Read setup.py and determine scope

# Verify
git status --short
```

**Agent Strategy**: Agent reads setup.py to determine if it should move or stay

**Success Criteria**:
- [ ] production_api_server.py in development/apps/api/
- [ ] mcp-health-monitor.js in development/services/mcp/
- [ ] setup.py decision made (move or keep)
- [ ] Any import references updated

**Time**: 20 minutes

---

### **Task 1B.5: Phase 1B Checkpoint**
```bash
git commit -m "phase: 1B complete - root-level code organization

✅ Created organized directory structure in development/
✅ Moved 10 webhook system files → development/services/webhooks/reactive/
✅ Moved 4 config files → development/config/
✅ Moved API server → development/apps/api/
✅ Moved MCP monitor → development/services/mcp/

Impact:
- Root Python files: 12 → 1 (setup.py - TBD)
- Root JS files: 1 → 0
- Root config files: 4 → 0
- Root directory: 92% cleaner!

Updated references:
- [List files with updated imports]
- [List files with updated config paths]

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Time**: 10 minutes

**Phase 1B Total**: ~2 hours

---

## 📋 PHASE 2: Major Project Reorganization

**Duration**: 3-4 hours
**Risk Level**: 🟠 Medium-High
**Estimated Completion**: Day 2, Session 1

### **Task 2.1: Move catalytic-computing-production**

**Agent Strategy**: Use agent to analyze dependencies and PYTHONPATH impact

**Step 1: Analysis Agent** 🔍
```
Agent Task: Analyze catalytic-computing-production/:
1. Check if it's a git submodule
2. List all external files importing from this directory
3. Identify if it has internal cross-references
4. Check for hardcoded paths in its files
5. Verify setup.py configuration

Return: Comprehensive impact analysis
```

**Step 2: Execute Move**
```bash
# Create target directory
mkdir -p development/apps/

# Move project (if NOT a submodule)
git mv catalytic-computing-production development/apps/

# OR if submodule:
git submodule deinit catalytic-computing-production
git rm catalytic-computing-production
git submodule add <url> development/apps/catalytic-computing-production
git submodule update --init --recursive
```

**Step 3: Update References** 📝
```
Agent Task: Update all imports and references:
1. Update imports in external files
2. Update any config files referencing this project
3. Verify no broken imports

Return: Validation report
```

**Success Criteria**:
- [ ] Project moved to development/apps/
- [ ] All imports updated
- [ ] No broken dependencies
- [ ] Project can be imported successfully

**Time**: 45 minutes

---

### **Task 2.2: Move catalytic-lattice-k8s-agents**

**Same agent strategy as Task 2.1**

```bash
# Create target
mkdir -p development/infrastructure/

# Move (check submodule status first)
git mv catalytic-lattice-k8s-agents development/infrastructure/
# OR use submodule commands if needed

# Verify
ls -la development/infrastructure/
```

**Time**: 45 minutes

---

### **Task 2.3: Move ghidra-claude Integration**

**Agent Strategy**: Special attention to ghidra_claude_config.json reference

```bash
# Create target structure
mkdir -p development/tools/ghidra/integrations/

# Move project
git mv ghidra-claude development/tools/ghidra/integrations/claude

# Verify config is accessible
# development/config/ghidra/ghidra_claude_config.json should still work

# Update any references
```

**Agent Task**: Find and update all references to ghidra-claude/ scripts

**Time**: 30 minutes

---

### **Task 2.4: Move shared/ Library** ⚠️ HIGH IMPACT

**Agent Strategy**: CRITICAL - This will affect PYTHONPATH and many imports

**Step 1: Impact Analysis Agent** 🔍
```
Agent Task: COMPREHENSIVE shared/ analysis:
1. Find ALL files importing from shared.*
2. List all internal cross-references within shared/
3. Identify any sys.path.append or PYTHONPATH modifications
4. Find documentation referencing shared/
5. Check for any build scripts or configs using shared/

Return: Complete dependency map
```

**Step 2: Update PYTHONPATH References**
```bash
# Read current README for PYTHONPATH instructions
cat shared/README.md

# Decide on strategy:
# Option A: Move and update all imports
# Option B: Move and create compatibility symlink
# Option C: Keep at root (if heavily used)
```

**Step 3: Execute Move (if proceeding)**
```bash
# Move to development
git mv shared development/libs/shared

# Update all imports (agent-assisted)
# from shared.utilities import X
# to
# from development.libs.shared.utilities import X

# OR update PYTHONPATH documentation
```

**Success Criteria**:
- [ ] Decision made (move vs keep)
- [ ] If moved: all imports updated
- [ ] If moved: PYTHONPATH documentation updated
- [ ] All dependent projects still functional

**Time**: 1-1.5 hours (due to high impact)

---

### **Task 2.5: Phase 2 Checkpoint**
```bash
git commit -m "phase: 2 complete - major project reorganization

✅ Moved catalytic-computing-production → development/apps/
✅ Moved catalytic-lattice-k8s-agents → development/infrastructure/
✅ Moved ghidra-claude → development/tools/ghidra/integrations/claude/
✅ [Moved | Retained] shared/ library [with rationale]

Impact:
- Root Python projects: 4 → 0 (100% organized)
- Development structure: Cleaner, more intuitive
- Import paths: [X files updated]

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Time**: 10 minutes

**Phase 2 Total**: ~3-4 hours

---

## 📋 PHASE 3: Demo Projects & Final Cleanup

**Duration**: 2-3 hours
**Risk Level**: 🟢 Low
**Estimated Completion**: Day 2-3, Session 2

### **Task 3.1: Move cosmos-viz to projects/**

```bash
# Verify directory exists
test -d cosmos-viz && echo "Found" || echo "Not found"

# Create target
mkdir -p projects/sandbox/

# Move
git mv cosmos-viz projects/sandbox/

# Verify
ls -la projects/sandbox/cosmos-viz/
```

**Time**: 15 minutes

---

### **Task 3.2: Decide on go-deployment-demo**

**Agent Strategy**: Analyze to determine if active or archival

```
Agent Task: Analyze go-deployment-demo/:
1. Check last modified date of files
2. Check if referenced in any active projects
3. Determine if it's demo code or production utility
4. Check size (8.3MB - significant)

Recommendation: Archive or move to development/demos/
```

**Option A: Active development**
```bash
git mv go-deployment-demo development/demos/go-deployment
```

**Option B: Archive**
```bash
tar -czf Archive/demos/go-deployment-demo-$(date +%Y%m%d).tar.gz go-deployment-demo/
git rm -r go-deployment-demo/
```

**Time**: 30 minutes

---

### **Task 3.3: Handle Untracked Items**

**Targets**:
- Tools/plugins/ghidra/GhidraEmu (untracked, possibly submodule)
- development/.backup_links_20251010/ (backup from previous consolidation)

```bash
# Investigate GhidraEmu
cd Tools/plugins/ghidra/GhidraEmu
git status
# If it's a submodule that should be tracked:
cd ../../../../
git submodule add <url> Tools/plugins/ghidra/GhidraEmu

# Handle backup directory
# If no longer needed:
rm -rf development/.backup_links_20251010/
# OR move to Archive
mv development/.backup_links_20251010/ Archive/backups/
```

**Time**: 30 minutes

---

### **Task 3.4: Resolve Modified Submodules**

**Current modified submodules**:
- development/services/mcp/PRIMS
- development/services/mcp/RepoMapper
- development/services/mcp/desktop-notify
- projects/active/ghidra
- projects/financial-apps/tldraw-demo

```bash
# For each submodule, either:

# Option A: Commit changes in submodule
cd development/services/mcp/PRIMS
git add -A
git commit -m "Update from main workspace"
git push
cd ../../../../
git add development/services/mcp/PRIMS
git commit -m "Update PRIMS submodule"

# Option B: Reset to clean state
git submodule update --recursive --remote

# Repeat for each modified submodule
```

**Agent Strategy**: Agent can check each submodule status and recommend action

**Time**: 45 minutes

---

### **Task 3.5: Phase 3 Checkpoint**
```bash
git commit -m "phase: 3 complete - demo projects and final cleanup

✅ Moved cosmos-viz → projects/sandbox/
✅ [Archived | Moved] go-deployment-demo [with rationale]
✅ Resolved untracked GhidraEmu submodule
✅ Cleaned up backup directory
✅ Resolved all modified submodules

Impact:
- All demo projects properly organized
- Submodules clean and synchronized
- Root directory: Professional structure achieved

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Time**: 10 minutes

**Phase 3 Total**: ~2-3 hours

---

## 📋 PHASE 4: Validation & Documentation

**Duration**: 1-2 hours
**Risk Level**: 🟢 Low (read-only verification)
**Estimated Completion**: Day 3, Session 1

### **Task 4.1: Run Automated Validation**

**Agent Strategy**: Use multiple agents for comprehensive validation

**Validation Agent 1: Import Testing** 🧪
```
Agent Task: Test all Python imports:
1. Try importing moved webhook modules
2. Try importing catalytic projects
3. Verify shared/ imports (if moved)
4. Test config loading from new paths

Return: Pass/fail for each import with error details if any
```

**Validation Agent 2: Path Reference Check** 🔍
```
Agent Task: Search entire codebase for:
1. Hardcoded paths to old locations
2. References to moved files
3. Broken symlinks
4. Documentation with outdated paths

Return: List of files still referencing old paths
```

**Validation Agent 3: Git Integrity** ✅
```
Agent Task: Verify git state:
1. No deleted files in git (should be moves only)
2. No large changes in diff (should be renames)
3. All submodules clean
4. No untracked files that should be tracked

Return: Git health report
```

**Time**: 45 minutes

---

### **Task 4.2: Update Documentation**

**Agent Strategy**: Documentation update agent

```
Agent Task: Update all README files and documentation:
1. development/README.md - update structure description
2. Root README.md - update project organization
3. DIRECTORY_ORGANIZATION_ROADMAP.md - mark phases complete
4. Any moved project READMEs - update relative paths

Return: List of documentation files updated
```

**Manual updates needed**:
- [ ] shared/README.md - PYTHONPATH instructions (if moved)
- [ ] development/services/webhooks/reactive/README.md - create if needed
- [ ] Root README - update project structure diagram

**Time**: 45 minutes

---

### **Task 4.3: Update Existing Planning Documents**

```bash
# Update status in planning documents
# - DIRECTORY_REMEDIATION_PLAN.md
# - DIRECTORY_ORGANIZATION_ROADMAP.md
# - development/docs/reports/DIRECTORY_CLEANUP_SUMMARY.md

# Mark phases complete
# Update organization score: 6.5/10 → 9.5/10
# Update metrics: files moved, directories cleaned, etc.
```

**Time**: 30 minutes

---

### **Task 4.4: Phase 4 Checkpoint**
```bash
git commit -m "phase: 4 complete - validation and documentation

✅ All Python imports validated
✅ No broken path references found
✅ Git integrity verified
✅ Documentation updated across all affected READMEs
✅ Planning documents marked complete

Validation results:
- Import tests: [X/X passed]
- Path references: [X] updated
- Git health: Clean
- Documentation: Comprehensive

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Time**: 10 minutes

**Phase 4 Total**: ~2 hours

---

## 📋 PHASE 5: Final Verification & Deployment

**Duration**: 1 hour
**Risk Level**: 🟢 None
**Estimated Completion**: Day 3, Session 2

### **Task 5.1: Directory Structure Audit**

```bash
# Count top-level directories
ls -1 | wc -l
# Target: ~25 (down from 58)

# Count root .py files
ls -1 *.py 2>/dev/null | wc -l
# Target: 0 (down from 12)

# Count root .json files
ls -1 *.json 2>/dev/null | wc -l
# Target: 0 (down from 4)

# Verify development/ structure
tree development/ -L 2 -d
```

**Success Criteria**:
- [ ] Top-level directories ≤ 30
- [ ] Root Python files = 0
- [ ] Root config files = 0
- [ ] Clean, professional structure

**Time**: 15 minutes

---

### **Task 5.2: Generate Final Report**

**Agent Strategy**: Use agent to generate comprehensive completion report

```
Agent Task: Generate DIRECTORY_REORGANIZATION_COMPLETION_REPORT.md:
1. List all moves executed (from → to)
2. Count files impacted
3. List all updated imports/references
4. Calculate organization score improvement
5. List remaining tasks (if any)
6. Generate before/after metrics comparison
7. Include git commit history for audit trail

Return: Complete markdown report
```

**Report sections**:
- Executive Summary
- Detailed Move Log
- Impact Analysis
- Validation Results
- Before/After Metrics
- Rollback Instructions (just in case)
- Maintenance Recommendations

**Time**: 30 minutes

---

### **Task 5.3: Update DIRECTORY_ORGANIZATION_ROADMAP.md**

```bash
# Mark Phase 2 complete in roadmap
# Update current organization score: 6.5 → 9.5
# Add completion date
# Note any deviations from plan
```

**Time**: 10 minutes

---

### **Task 5.4: Final Commit & Tag**
```bash
git commit -m "phase: 5 complete - DIRECTORY REORGANIZATION COMPLETE ✅

🎉 Successfully reorganized C:\Users\Corbin\ directory structure

## Summary Statistics:
- Root Python files: 12 → 0 (100% cleanup)
- Root config files: 4 → 0 (100% cleanup)
- Top-level directories: 58 → 25 (57% reduction)
- Organization score: 6.5/10 → 9.5/10 (+46% improvement)

## Projects Reorganized:
✅ 12 webhook system files → development/services/webhooks/reactive/
✅ catalytic-computing-production → development/apps/
✅ catalytic-lattice-k8s-agents → development/infrastructure/
✅ ghidra-claude → development/tools/ghidra/integrations/claude/
✅ 4 config files → development/config/
✅ cosmos-viz → projects/sandbox/
✅ Large files → Archive/

## Validation:
✅ All imports tested and passing
✅ No broken references
✅ Git integrity verified
✅ Documentation comprehensive
✅ Submodules synchronized

## Key Achievements:
- Professional, maintainable directory structure
- Clear separation of concerns
- Improved discoverability
- Reduced root directory clutter
- Enhanced scalability for future projects

## Timeline:
- Phase 0: Pre-flight checks - Complete
- Phase 1A: Critical fixes - Complete
- Phase 1B: Root organization - Complete
- Phase 2: Major projects - Complete
- Phase 3: Final cleanup - Complete
- Phase 4: Validation - Complete
- Phase 5: Deployment - Complete

Total effort: ~8-10 hours over 3 days

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# Create commemorative tag
git tag -a v2.0-directory-reorganization -m "Major directory reorganization complete - Professional structure achieved"
```

**Time**: 5 minutes

**Phase 5 Total**: ~1 hour

---

## 🎯 Success Metrics

### **Primary KPIs**
| Metric | Before | Target | Actual |
|--------|---------|--------|--------|
| Root Python files | 12 | 0 | TBD |
| Root config files | 4 | 0 | TBD |
| Top-level directories | 58 | ≤30 | TBD |
| Organization score | 6.5/10 | 9.5/10 | TBD |

### **Secondary KPIs**
- [ ] All tests passing
- [ ] No broken imports
- [ ] Zero git integrity issues
- [ ] Documentation 100% updated
- [ ] All planning docs marked complete

---

## 🤖 Agent Utilization Summary

### **Agents Deployed**:
1. **Discovery Agent** (Phase 1B, 2): Find dependencies and references
2. **Validation Agent** (Phase 1B, 2, 4): Test imports and paths
3. **Documentation Agent** (Phase 4): Update all documentation
4. **Analysis Agent** (Phase 2): Project dependency analysis
5. **Report Generator Agent** (Phase 5): Final completion report

### **Agent Benefits**:
- ⚡ **Speed**: Parallel searches across large codebase
- 🎯 **Accuracy**: Comprehensive reference discovery
- 📊 **Thoroughness**: Multi-file validation
- 📝 **Documentation**: Auto-generated reports

---

## 📅 Recommended Schedule

### **Day 1: Foundations**
- **Session 1** (2 hours): Phase 1A (critical fixes)
- **Session 2** (2-3 hours): Phase 1B (root cleanup)

### **Day 2: Major Moves**
- **Session 1** (3-4 hours): Phase 2 (project reorganization)
- **Session 2** (2-3 hours): Phase 3 (final cleanup)

### **Day 3: Validation**
- **Session 1** (2 hours): Phase 4 (validation)
- **Session 2** (1 hour): Phase 5 (final deployment)

**Total**: 10-13 hours over 3 days

---

## 🚨 Risk Mitigation

### **High-Risk Items**:
1. **shared/ library move** - May break many imports
   - Mitigation: Create temporary symlink, update gradually

2. **Git submodule handling** - Requires special commands
   - Mitigation: Document current state, use proper submodule commands

3. **Import path changes** - Could break running applications
   - Mitigation: Use agents to find ALL references before moving

### **Rollback Triggers**:
- Multiple import errors after moves
- Git corruption or submodule issues
- Critical application failures
- More than 10 files with broken references

**If triggered**: `git reset --hard 90adb26` + manual cleanup

---

## 📚 References

### **Related Documents**:
- DIRECTORY_REMEDIATION_PLAN.md (root)
- development/DIRECTORY_ORGANIZATION_ROADMAP.md
- development/docs/reports/DIRECTORY_CLEANUP_SUMMARY.md
- development/docs/reports/ACTIVE_PROJECTS_INVENTORY.md

### **Git Checkpoints**:
- `90adb26` - Pre-Phase 1A checkpoint (safety)
- TBD - Post-Phase 1A checkpoint
- TBD - Post-Phase 1B checkpoint
- TBD - Post-Phase 2 checkpoint
- TBD - Post-Phase 3 checkpoint
- TBD - Final completion

---

## ✅ Execution Checklist

### **Before Starting**:
- [x] Git checkpoint created
- [x] Current directory structure documented
- [x] All target files verified to exist
- [ ] Team notified (if applicable)
- [ ] Backup created (optional but recommended)

### **During Execution**:
- [ ] Follow phase order strictly
- [ ] Create checkpoint after each phase
- [ ] Verify success criteria before proceeding
- [ ] Document any deviations from plan
- [ ] Use agents for complex analysis tasks

### **After Completion**:
- [ ] All success metrics achieved
- [ ] Final report generated
- [ ] Planning documents updated
- [ ] Tag created for this milestone
- [ ] Optional: Blog post or documentation of learnings

---

**Plan Status**: ✅ READY FOR EXECUTION
**Next Action**: Proceed with Phase 1A, Task 1.1 (Fix KA Lattice numpy bug)
**Estimated Completion**: October 12-13, 2025

---

*This deployment plan was generated with systematic analysis and agent-based automation strategies for maximum efficiency and safety.*

**Last Updated**: October 10, 2025, 16:00 PST
