# Development Directory Cleanup - Execution Plan

**Date:** October 8, 2025
**Target:** `C:\Users\Corbin\development`
**Current Status:** 200 root-level files → Target: ~40 files (80% reduction)

---

## Executive Summary

This plan addresses **documentation sprawl** with 125+ markdown files cluttering the root directory. We'll safely archive historical completion reports while maintaining accessibility, reorganize misplaced test files, and eliminate 30MB of cache files.

**Key Metrics:**
- **Files to archive:** 70+ status reports
- **Files to relocate:** 26 test/utility scripts
- **Files to delete:** 5 cache directories + obsolete files
- **Disk space recovery:** ~30 MB immediate
- **Time required:** 2-4 hours total

---

## Safety Precautions

### Before Starting

✅ **Create a backup:**
```bash
cd /c/Users/Corbin
tar -czf development-backup-$(date +%Y%m%d).tar.gz development/
# Or use Windows backup
```

✅ **Verify Git status:**
```bash
cd development
git status
git add -A
git commit -m "Pre-cleanup snapshot"
```

✅ **Test critical scripts:**
```bash
# Verify key functionality still works
python test_gpu_refactoring_simple.py
```

---

## Phase 1: Immediate Cleanup (30 minutes)

### Step 1.1: Delete Cache Directories (~30 MB recovery)

```bash
cd /c/Users/Corbin/development

# Delete Python caches
rm -rf .mypy_cache/
rm -rf .ruff_cache/
rm -rf .pytest_cache/
rm -rf __pycache__/

# Delete orphaned file
rm -f nul

# Verify deletion
echo "Cache cleanup complete. Recovered ~30 MB"
```

**Safety:** These are all regenerable caches. No data loss.

---

### Step 1.2: Delete Explicitly Obsolete Files

```bash
# Files marked as OLD or IN_PROGRESS (now completed)
rm -f DEPLOYMENT_COMPLETE_OLD.md
rm -f LOAD_TESTING_IN_PROGRESS.md

# Duplicate text files (covered by markdown versions)
rm -f PRODUCTION_READINESS_REPORT.txt

# Small result files (can regenerate)
rm -f escape_prevention_results.txt
rm -f validation_results.txt

echo "Obsolete files removed"
```

---

### Step 1.3: Create New Directory Structure

```bash
# Documentation organization
mkdir -p docs/archive/{phase-reports,week-reports,deployment-history,2025-Q4}
mkdir -p docs/{specifications,guides,reports,conversations}

# Code organization
mkdir -p tests/{gpu,benchmarks}
mkdir -p scripts/{utilities,troubleshooting,deployment}

# Results and visualizations
mkdir -p visualizations
mkdir -p results/{gpu,security}

# Data and backups
mkdir -p backups

echo "Directory structure created"
```

---

## Phase 2: Archive Historical Documentation (1 hour)

### Step 2.1: Archive Phase Completion Reports

```bash
cd /c/Users/Corbin/development

# Move all PHASE completion reports
mv PHASE1_COMPLETION_SUMMARY.md docs/archive/phase-reports/
mv PHASE2_100_PERCENT_COMPLETE.md docs/archive/phase-reports/
mv PHASE2_COMPLETE.md docs/archive/phase-reports/
mv PHASE2_COMPLETION_REPORT.md docs/archive/phase-reports/
mv PHASE2_DEPLOYMENT_SUMMARY.md docs/archive/phase-reports/
mv PHASE2_DEPLOYMENT_VERIFICATION.md docs/archive/phase-reports/
mv PHASE2_FINAL_STATUS.md docs/archive/phase-reports/
mv PHASE2_MEMORY_MANAGEMENT_COMPLETE.md docs/archive/phase-reports/
mv phase2_success_summary.md docs/archive/phase-reports/
mv PHASE3_BATCH_PROCESSING_COMPLETE.md docs/archive/phase-reports/
mv PHASE3_PLAN.md docs/archive/phase-reports/
mv PHASE4_GPU_PROFILER_COMPLETE.md docs/archive/phase-reports/
mv PHASE4_PLAN.md docs/archive/phase-reports/
mv PHASE_3_VALIDATION_REPORT.md docs/archive/phase-reports/
mv PHASE_4_COMPLETION_SUMMARY.md docs/archive/phase-reports/
mv PHASE_4_STATUS_REPORT.md docs/archive/phase-reports/
mv PHASE_5_ROADMAP.md docs/archive/phase-reports/

echo "Phase reports archived: $(ls docs/archive/phase-reports/ | wc -l) files"
```

---

### Step 2.2: Archive Weekly Reports

```bash
# Move all WEEK reports
mv WEEK1_COMPLETION_SUMMARY.md docs/archive/week-reports/
mv WEEK1_REVIEW_REPORT.md docs/archive/week-reports/
mv WEEK2_COMPLETE_SUMMARY.md docs/archive/week-reports/
mv WEEK2_DAY1_E2E_TESTING_COMPLETE.md docs/archive/week-reports/
mv WEEK2_DAY2_CHAOS_TESTING_COMPLETE.md docs/archive/week-reports/
mv WEEK3_COMPREHENSIVE_LOAD_TESTING_FINAL_REPORT.md docs/archive/week-reports/
mv WEEK3_DAY1_LOAD_TESTING_EXECUTION_COMPLETE.md docs/archive/week-reports/
mv WEEK3_DAY1_LOAD_TESTING_READY.md docs/archive/week-reports/
mv WEEK3_DAY2-3_REDIS_INTEGRATION_COMPLETE.md docs/archive/week-reports/
mv WEEK3_DAY2-3_SYSTEMATIC_EXECUTION_PLAN.md docs/archive/week-reports/
mv WEEK_2_VALIDATION_REPORT.md docs/archive/week-reports/

echo "Weekly reports archived: $(ls docs/archive/week-reports/ | wc -l) files"
```

---

### Step 2.3: Archive Deployment History

```bash
# Move deployment completion reports
mv DEPLOYMENT_COMPLETE_2025-10-05.md docs/archive/deployment-history/
mv DEPLOYMENT_COMPLETE_SUMMARY.md docs/archive/deployment-history/
mv DEPLOYMENT_SUMMARY.md docs/archive/deployment-history/
mv FINAL_DEPLOYMENT_SUMMARY.md docs/archive/deployment-history/
mv PRODUCTION_DEPLOYMENT_2025.md docs/archive/deployment-history/
mv PRODUCTION_STATUS_2025-10-05.md docs/archive/deployment-history/
mv SECURITY_DEPLOYMENT_SUMMARY.md docs/archive/deployment-history/

# Keep DEPLOYMENT_STATUS_CURRENT.md at root (it's current!)

echo "Deployment history archived: $(ls docs/archive/deployment-history/ | wc -l) files"
```

---

### Step 2.4: Archive BMAD/Redis Completion Reports

```bash
# These are completed, archive for reference
mv B_MAD_DEPLOYMENT_COMPLETE.md docs/archive/2025-Q4/
mv B_MAD_REDIS_OPTIMIZATION_COMPLETE.md docs/archive/2025-Q4/
mv BMAD_COMPLETION_REPORT.md docs/archive/2025-Q4/
mv BMAD_DEPLOYMENT_READY.md docs/archive/2025-Q4/
mv BMAD_SETUP_COMPLETE.md docs/archive/2025-Q4/
mv NVIDIA_BMAD_DEPLOYMENT_STATUS.md docs/archive/2025-Q4/
mv NVIDIA_DEPLOYMENT_COMPLETE.md docs/archive/2025-Q4/
mv REDIS_OPTIMIZATION_COMPLETE.md docs/archive/2025-Q4/
mv REDIS_POOL_PRODUCTION_INTEGRATION.md docs/archive/2025-Q4/
mv REDIS_PRODUCTION_DEPLOYMENT_COMPLETE.md docs/archive/2025-Q4/
mv REDIS_SERVER_STARTUP_SUCCESS.md docs/archive/2025-Q4/

# Keep active guides at root or in docs/guides/
# BMAD_NEXT_STEPS_EXECUTION_PLAN.md - keep (planning doc)
# NVIDIA_BMAD_DEPLOYMENT_PLAN.md - move to docs/guides/
mv NVIDIA_BMAD_DEPLOYMENT_PLAN.md docs/guides/
mv REDIS_TESTING_MANUAL.md docs/guides/

echo "BMAD/Redis completion reports archived"
```

---

### Step 2.5: Archive Security Completion Reports

```bash
# Move security validation completions
mv ARBITRARY_IMAGE_SCENARIO_DEFENSE_VALIDATION.md docs/archive/2025-Q4/
mv CRITICAL_SECURITY_FIXES_COMPLETE.md docs/archive/2025-Q4/
mv D3FEND_COMPLIANCE_ACHIEVED.md docs/archive/2025-Q4/
mv D3FEND_INTEGRATION_SUMMARY.md docs/archive/2025-Q4/
mv D3FEND_SECURITY_FIXES_VALIDATION.md docs/archive/2025-Q4/
mv HOST_PROTECTION_VALIDATION.md docs/archive/2025-Q4/
mv SECURITY_REMEDIATION_SESSION_SUMMARY.md docs/archive/2025-Q4/
mv SECURITY_VALIDATION_REPORT.md docs/archive/2025-Q4/
mv SECURITY_VALIDATION_SUCCESS.md docs/archive/2025-Q4/

# Keep active security docs
mv D3FEND_NEXT_STEPS.md docs/reports/
mv DEFENSIVE_SECURITY_AGENT_ARCHITECTURE.md docs/specifications/
mv WIZ_ZERODAY_CLOUD_2025_DEFENSE_STRATEGY.md docs/specifications/

echo "Security completion reports archived"
```

---

### Step 2.6: Archive GPU/Performance Completion Reports

```bash
# Move GPU optimization completions
mv ADVANCED_PROFILING_COMPLETE.md docs/archive/2025-Q4/
mv GPU_ENHANCEMENTS_COMPLETE.md docs/archive/2025-Q4/
mv GPU_OPTIMIZATION_COMPLETE.md docs/archive/2025-Q4/
mv GPU_OPTIMIZATION_FINAL_SUMMARY.md docs/archive/2025-Q4/
mv GPU_TEST_RESULTS.md docs/archive/2025-Q4/
mv NUMBA_CUDA_TROUBLESHOOTING_REPORT.md docs/archive/2025-Q4/
mv NUMBA_TROUBLESHOOTING_COMPLETE.md docs/archive/2025-Q4/

echo "GPU completion reports archived"
```

---

### Step 2.7: Archive General Completion Reports

```bash
# Move general completion reports
mv IMPLEMENTATION_SUMMARY.md docs/archive/2025-Q4/
mv INSTRUMENTATION_COMPLETE.md docs/archive/2025-Q4/
mv INTEGRATION_COMPLETE_2025-10-05.md docs/archive/2025-Q4/
mv MCP_DEPLOYMENT_COMPLETION_REPORT.md docs/archive/2025-Q4/
mv QUALITY_IMPROVEMENTS_COMPLETE.md docs/archive/2025-Q4/
mv REMEDIATION_COMPLETE.md docs/archive/2025-Q4/
mv SYSTEMATIC_EXECUTION_DAY1_REVIEW.md docs/archive/2025-Q4/
mv SYSTEMATIC_EXECUTION_SUMMARY.md docs/archive/2025-Q4/

echo "General completion reports archived"
```

---

### Step 2.8: Organize Planning Documents

```bash
# Archive old planning docs
mv CLEANUP_PLAN_PHASE2.md docs/archive/2025-Q4/
mv SYSTEMATIC_DEPLOYMENT_PLAN.md docs/archive/2025-Q4/
mv SYSTEMATIC_EXECUTION_PLAN_2025-10-05.md docs/archive/2025-Q4/
mv DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md docs/archive/2025-Q4/

# Keep active planning docs or move to docs/reports/
mv NEXT_STEPS_PLAN_2025-10-03.md docs/reports/
mv COMMANDS_AND_SHORTCUTS_IMPLEMENTATION_PLAN.md docs/reports/

# Or keep BMAD_NEXT_STEPS at root if actively referencing

echo "Planning documents organized"
```

---

## Phase 3: Reorganize Code Files (45 minutes)

### Step 3.1: Move Test Files to tests/

```bash
cd /c/Users/Corbin/development

# Move GPU test files
mv check_pdf_tools.py tests/gpu/
mv cupy-with-pytorch-cuda.py tests/gpu/
mv fix-cupy-cuda.py tests/gpu/
mv gpu-libraries-comprehensive-test.py tests/gpu/
mv gpu-libraries-test.py tests/gpu/
mv gpu-troubleshooting-diagnostics.py tests/gpu/
mv numba-setup-test.py tests/gpu/
mv test-gpu-full-stack.py tests/gpu/
mv test-numba-cuda-modern.py tests/gpu/
mv test-numba-cuda.py tests/gpu/
mv test_gpu_refactoring_simple.py tests/gpu/

# Move benchmark files
mv gpu-performance-benchmark.py tests/benchmarks/
mv matrix-optimization-benchmark.py tests/benchmarks/

echo "Test files relocated: $(ls tests/gpu/ | wc -l) files in tests/gpu/"
echo "Benchmark files relocated: $(ls tests/benchmarks/ | wc -l) files"
```

---

### Step 3.2: Move Utility Scripts

```bash
# Move PDF conversion utilities
mv convert_ascii_to_pdf.py scripts/utilities/
mv convert_to_pdf.bat scripts/utilities/
mv create_mernithian_pdf.py scripts/utilities/
mv create_pdf_from_ascii.py scripts/utilities/
mv glyph_svg_exporter.py scripts/utilities/

# Move other utilities
mv update-imports.py scripts/utilities/
mv migration-rollback.py scripts/utilities/

echo "Utility scripts relocated: $(ls scripts/utilities/ | wc -l) files"
```

---

### Step 3.3: Move Deployment Scripts

```bash
# Keep deploy scripts organized
mv deploy-ka-lattice-local.py scripts/deployment/
mv fold7_ssh_monitor.py scripts/deployment/

echo "Deployment scripts organized"
```

---

## Phase 4: Organize Supporting Files (30 minutes)

### Step 4.1: Move Visualizations

```bash
# Move all HTML visualization files
mv ascii_portraits_collection.html visualizations/
mv gpu-optimization-visualization.html visualizations/
mv mernithian_conversation.html visualizations/
mv mernithian_proof_visualization.html visualizations/
mv profiler_visualization.html visualizations/
mv profiler_visualization_v2.html visualizations/
mv project-ecosystem-visualization.html visualizations/

echo "Visualizations organized: $(ls visualizations/ | wc -l) HTML files"
```

---

### Step 4.2: Move Conversation/Narrative Files

```bash
# Move conversation markdown files
mv ascii_portraits_collection.md docs/conversations/
mv cognitive_warfare_conversation.md docs/conversations/
mv mernithian_conversation.md docs/conversations/

echo "Conversation files organized"
```

---

### Step 4.3: Move Results and Metrics

```bash
# Move GPU metrics
mv gpu_baseline_metrics.json results/gpu/
mv memory-optimization-results.json results/gpu/

echo "Results files organized"
```

---

### Step 4.4: Move Backup Files

```bash
# Move large backup file
mv ka_knowledge_backup.json backups/
mv proof_library.json backups/

echo "Backup files organized"
```

---

### Step 4.5: Organize Technical Specifications

```bash
# Move specification documents
mv FRAMEWORK_CAPABILITY_ASSESSMENT.md docs/specifications/
mv GHIDRAGO_SPECIFICATION.md docs/specifications/
mv GHIDRAGO_SPEC_REVIEW.md docs/specifications/
mv GHIDRA_EXTENSIONS.md docs/specifications/
mv GHIDRA_EXTENSIONS_SUMMARY.md docs/specifications/
mv GHIDRASSIST_ANALYSIS.md docs/specifications/
mv JWT_CONSOLIDATION_ANALYSIS.md docs/specifications/
mv CONFIGURATION_AUDIT_REPORT.md docs/specifications/

echo "Specifications organized"
```

---

### Step 4.6: Organize Guides

```bash
# Move operational guides
mv FOLD7_README.md docs/guides/
mv FOLD7_SSH_SETUP.md docs/guides/
mv IDENTIFY_YOUR_SSH_APP.md docs/guides/
mv TERMUX_DESKTOP_SSH.md docs/guides/
mv setup_xnano_ssh_server.md docs/guides/
mv ka-lattice-deployment-guide.md docs/guides/
mv saas-deployment-guide.md docs/guides/
mv ENV_CONFIGURATION_GUIDE.md docs/guides/
mv REDIS_POOL_OPTIMIZATION_GUIDE.md docs/guides/
mv REDIS_POOL_PERFORMANCE_REPORT.md docs/guides/
mv STRIPE_EMAIL_INTEGRATION_GUIDE.md docs/guides/

# Keep QUICK_START_GUIDE.md and QUICK_DEPLOY.md at root for easy access

echo "Guides organized"
```

---

### Step 4.7: Organize Active Reports

```bash
# Move active reports
mv GRAFANA_DASHBOARDS_SUMMARY.md docs/reports/
mv LINTING_REPORT.md docs/reports/
mv REFACTORING_SUMMARY.md docs/reports/
mv PRODUCTION_READY_CHECKLIST.md docs/reports/
mv PRODUCTION_READY_REPORT.md docs/reports/
mv gpu-final-status-report.md docs/reports/

echo "Active reports organized"
```

---

## Phase 5: Create Index Documents (15 minutes)

### Step 5.1: Create Archive Index

```bash
cat > docs/archive/README.md << 'EOF'
# Documentation Archive

This directory contains historical completion reports, phase summaries, and deployment history.

## Directory Structure

- **phase-reports/** - Phase 1-5 completion reports and summaries
- **week-reports/** - Weekly progress reports (Weeks 1-3)
- **deployment-history/** - Historical deployment summaries
- **2025-Q4/** - Q4 2025 completion reports (BMAD, Redis, Security, GPU)

## Finding Documents

### By Phase
- Phase 1: `phase-reports/PHASE1_COMPLETION_SUMMARY.md`
- Phase 2: `phase-reports/PHASE2_*.md`
- Phase 3: `phase-reports/PHASE3_*.md`
- Phase 4: `phase-reports/PHASE4_*.md`

### By Topic
- BMAD/Redis: `2025-Q4/BMAD_*.md`, `2025-Q4/REDIS_*.md`
- Security: `2025-Q4/*SECURITY*.md`, `2025-Q4/D3FEND_*.md`
- GPU: `2025-Q4/GPU_*.md`
- Deployment: `deployment-history/DEPLOYMENT_*.md`

### By Time
- Week 1: `week-reports/WEEK1_*.md`
- Week 2: `week-reports/WEEK2_*.md`
- Week 3: `week-reports/WEEK3_*.md`

## Note

These documents are preserved for historical reference and lessons learned.
For current project status, see the main project README and active documentation in the parent docs/ directory.
EOF

echo "Archive index created"
```

---

### Step 5.2: Update Main Documentation Index

```bash
cat > docs/README.md << 'EOF'
# Project Documentation

## Quick Links

- [Quick Start Guide](../QUICK_START_GUIDE.md)
- [Quick Deploy](../QUICK_DEPLOY.md)
- [Main README](../README.md)

## Documentation Structure

### Guides
Operational guides for deployment, configuration, and usage.
- See [guides/](guides/) directory

### Specifications
Technical specifications and architecture documents.
- See [specifications/](specifications/) directory

### Reports
Active reports and summaries.
- See [reports/](reports/) directory

### API Documentation
API references and integration guides.
- See [api/](api/) directory

### Archive
Historical completion reports and project milestones.
- See [archive/](archive/) directory

## For Developers

- **Tests:** See `../tests/` directory
- **Scripts:** See `../scripts/` directory
- **Docker:** Docker compose files at project root

## Contributing

When adding documentation:
1. Place active guides in `guides/`
2. Place technical specs in `specifications/`
3. Place status reports in `reports/`
4. Archive completed reports in `archive/`
EOF

echo "Main documentation index updated"
```

---

## Phase 6: Validation (15 minutes)

### Step 6.1: Verify File Counts

```bash
cd /c/Users/Corbin/development

echo "=== Root Level File Count ==="
ls -1 | wc -l
echo "Target: ~40 files"
echo ""

echo "=== Documentation Files at Root ==="
ls -1 *.md | wc -l
echo "Target: ~10 files"
echo ""

echo "=== Archived Files ==="
find docs/archive -type f | wc -l
echo ""

echo "=== Test Files in tests/ ==="
find tests -name "*.py" | wc -l
echo ""

echo "=== Utility Scripts ==="
ls scripts/utilities/ | wc -l
```

---

### Step 6.2: Verify No Broken References

```bash
# Check if any markdown files reference moved files
echo "Checking for broken references..."
grep -r "\.md)" docs/*.md 2>/dev/null | grep -v "archive" || echo "No obvious broken links in root docs"

# Check if key scripts still work
python tests/gpu/test_gpu_refactoring_simple.py || echo "Test script needs path updates"
```

---

### Step 6.3: Update .gitignore if Needed

```bash
cat >> .gitignore << 'EOF'

# Cache directories (should be excluded)
.mypy_cache/
.ruff_cache/
.pytest_cache/
__pycache__/

# Backup files
backups/

# Results
results/
EOF

echo ".gitignore updated"
```

---

## Phase 7: Final Commit (5 minutes)

```bash
cd /c/Users/Corbin/development

# Stage all changes
git add -A

# Commit with detailed message
git commit -m "refactor: massive documentation cleanup - 80% root file reduction

- Archived 70+ historical completion reports to docs/archive/
  - Phase reports (17 files)
  - Week reports (11 files)
  - Deployment history (7 files)
  - BMAD/Redis completions (11 files)
  - Security validations (9 files)
  - GPU optimizations (7 files)

- Reorganized code files
  - Moved 11 test files to tests/gpu/
  - Moved 2 benchmark files to tests/benchmarks/
  - Moved 7 utility scripts to scripts/utilities/
  - Moved 2 deployment scripts to scripts/deployment/

- Organized supporting files
  - Moved 7 HTML visualizations to visualizations/
  - Moved 3 conversation files to docs/conversations/
  - Moved 8 specifications to docs/specifications/
  - Moved 11 guides to docs/guides/
  - Moved 6 reports to docs/reports/

- Cleanup
  - Deleted 30 MB of cache directories
  - Removed 3 obsolete files
  - Moved large backups to backups/

Result: Root directory reduced from 200 to ~40 files (80% reduction)
Improved navigation, organization, and maintainability."

echo "Changes committed to git"
```

---

## Success Criteria

✅ **Root directory has ≤50 files** (down from 200)
✅ **Documentation files at root ≤15** (down from 125+)
✅ **All test files in tests/** (was 13 at root, now 0)
✅ **Cache directories deleted** (~30 MB recovered)
✅ **Historical reports archived** (accessible in docs/archive/)
✅ **Key scripts still functional** (tests pass)
✅ **Git history preserved** (all changes committed)

---

## Rollback Plan

If issues arise, rollback is simple:

```bash
# Restore from git
git reset --hard HEAD~1

# Or restore from backup
cd /c/Users/Corbin
tar -xzf development-backup-YYYYMMDD.tar.gz
```

---

## Post-Cleanup Actions

1. **Update CI/CD paths** if any pipelines reference moved files
2. **Update IDE workspace** to reflect new structure
3. **Notify team** of new organization (if applicable)
4. **Update README** with new directory structure
5. **Create shortcuts** to frequently accessed docs

---

## Maintenance Going Forward

### Rules for New Files

1. **Documentation:**
   - Active guides → `docs/guides/`
   - Technical specs → `docs/specifications/`
   - Status reports → `docs/reports/`
   - Completed reports → `docs/archive/` (quarterly)

2. **Code:**
   - Tests → `tests/`
   - Scripts → `scripts/`
   - Utilities → `scripts/utilities/`

3. **Supporting:**
   - Visualizations → `visualizations/`
   - Results → `results/`
   - Backups → `backups/`

### Quarterly Cleanup

Schedule quarterly reviews (Q1, Q2, Q3, Q4) to:
- Archive completed documentation
- Clean up obsolete test files
- Review and consolidate duplicate reports
- Update archive indexes

---

## Questions & Support

**Q: What if I need to find an old report?**
A: Check `docs/archive/README.md` for index and search by phase, topic, or time.

**Q: Will this break any scripts?**
A: Scripts referencing moved files may need path updates. The validation phase catches these.

**Q: Can I restore a specific file?**
A: Yes! Use `git log --all --full-history -- path/to/file` to find it, then `git checkout <commit> -- path/to/file`

**Q: How do I prevent this from happening again?**
A: Follow the "Rules for New Files" above and schedule quarterly cleanups.

---

**Status:** Ready for execution
**Estimated Time:** 2-4 hours
**Difficulty:** Low (mostly moving files)
**Risk:** Very Low (git + backup protection)

