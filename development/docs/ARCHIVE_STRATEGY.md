# Documentation Archive Strategy

**Purpose:** Define when and how to archive outdated documentation to maintain a clean, current documentation set.

---

## Archive Criteria

Documentation should be archived when it meets ANY of these conditions:

### 1. **Time-Based Archival**
- Documentation is **>6 months old** AND no longer actively referenced
- Project phase has completed and historical record is sufficient
- Technology/approach has been superseded by newer implementation

### 2. **Relevance-Based Archival**
- Feature has been removed from the codebase
- Architecture has been completely redesigned
- Information is obsolete or contradicts current implementation

### 3. **Consolidation-Based Archival**
- Information has been merged into a more comprehensive guide
- Multiple small docs have been consolidated into one master doc
- Duplicate content exists in better-maintained location

---

## What NOT to Archive

**Keep these documents active:**
- ✅ Currently referenced by active code or other docs
- ✅ Describes production systems or deployed features
- ✅ Contains unique historical context not captured elsewhere
- ✅ Serves as migration guide for ongoing transitions
- ✅ Documents current architecture or design decisions

---

## Archive Process

### Step 1: Identify Candidates
Run monthly review using these checks:

```bash
# Find docs not modified in 6+ months
find docs/ -name "*.md" -mtime +180

# Check git history for active references
git log --since="6 months ago" --name-only | grep "docs/"

# Search codebase for references to doc files
grep -r "docs/" --include="*.py" --include="*.go" --include="*.md"
```

### Step 2: Archive Structure

Move documents to dated archive folders:

```
docs/archive/
├── 2025-Q1/          # Jan-Mar 2025
├── 2025-Q2/          # Apr-Jun 2025
├── 2025-Q3/          # Jul-Sep 2025
└── 2025-Q4/          # Oct-Dec 2025
    ├── planning/     # Phase planning docs
    ├── reports/      # Completed project reports
    ├── guides/       # Superseded guides
    └── README.md     # Archive index with context
```

### Step 3: Create Archive Record

Each archive folder gets a README.md:

```markdown
# 2025-Q4 Documentation Archive

**Archive Date:** 2025-12-31
**Reason:** Quarterly documentation cleanup

## Archived Documents

| Document | Original Location | Reason | Superseded By |
|----------|------------------|--------|---------------|
| OLD_GPU_GUIDE.md | /docs/guides/ | Technology changed | GPU_ACCELERATION_GUIDE.md |
| PHASE_3_PLAN.md | /docs/ | Phase completed | PRODUCTION_READY_REPORT.md |
```

### Step 4: Update References

Before archiving, update all references:

1. **Search for incoming links:**
   ```bash
   grep -r "path/to/doc.md" docs/
   ```

2. **Update links to point to archive OR replacement:**
   - If replacement exists: Point to new doc
   - If historical reference: Update to archive path
   - If no longer relevant: Remove link entirely

3. **Add redirect note in archived doc (top of file):**
   ```markdown
   > **⚠️ ARCHIVED:** This document was archived on 2025-12-31.
   > See [NEW_DOC.md](../path/to/NEW_DOC.md) for current information.
   ```

### Step 5: Commit the Archive

```bash
git mv docs/OLD_DOC.md docs/archive/2025-Q4/OLD_DOC.md
git add docs/archive/2025-Q4/README.md
git commit -m "docs: archive Q4 2025 outdated documentation

- Moved OLD_DOC.md to archive (superseded by NEW_DOC.md)
- Created archive index with context
- Updated all references to point to current docs"
```

---

## Archive Schedule

| Frequency | Activity | Owner |
|-----------|----------|-------|
| **Monthly** | Review docs for archive candidates | Documentation Lead |
| **Quarterly** | Execute archival of identified docs | Development Team |
| **Annually** | Compress/backup old archives | DevOps |

---

## Archive Access

**Finding archived documents:**

1. **Check INDEX.md Archive section:**
   - Links to quarterly archives with descriptions

2. **Search git history:**
   ```bash
   git log --all --full-history -- "docs/archive/**"
   ```

3. **Use git grep for historical content:**
   ```bash
   git grep "search term" $(git rev-list --all -- docs/)
   ```

---

## Restoration Process

If archived documentation becomes relevant again:

1. **Assess current accuracy:**
   - Review for outdated information
   - Check if technical details still apply
   - Verify links and references

2. **Update before restoration:**
   - Correct outdated information
   - Update links to current docs
   - Add timestamp: `*Restored from archive: YYYY-MM-DD*`

3. **Move back to active docs:**
   ```bash
   git mv docs/archive/YYYY-QX/DOC.md docs/appropriate/location/
   ```

4. **Update INDEX.md to include restored doc**

---

## Examples

### Example 1: Superseded Technology Guide

**Scenario:** CUDA 12.x guide replaced by CUDA 13.x guide

```bash
# Archive the old guide
git mv docs/guides/CUDA_12_GUIDE.md docs/archive/2025-Q4/CUDA_12_GUIDE.md

# Add redirect at top of archived file
echo "> **⚠️ ARCHIVED:** CUDA 12.x is no longer supported. See [CUDA 13.x Guide](../../guides/CUDA_13_GUIDE.md)" | cat - docs/archive/2025-Q4/CUDA_12_GUIDE.md > temp && mv temp docs/archive/2025-Q4/CUDA_12_GUIDE.md

# Update all references
grep -rl "CUDA_12_GUIDE.md" docs/ | xargs sed -i 's|CUDA_12_GUIDE.md|CUDA_13_GUIDE.md|g'
```

### Example 2: Completed Project Phase

**Scenario:** Phase 3 planning complete, results documented

```bash
# Archive planning docs
git mv docs/PHASE_3_PLAN.md docs/archive/2025-Q3/planning/

# Keep results in active reports
# (No move needed for PHASE_3_RESULTS.md)

# Update phase index
vim docs/archive/2025-Q3/README.md
```

---

## Benefits of This Strategy

1. **Clean Active Documentation**
   - Easier to find current information
   - Reduces cognitive load for new team members
   - Improves search relevance

2. **Preserved History**
   - Historical context available when needed
   - Audit trail of decision-making
   - Reference for similar future projects

3. **Link Integrity**
   - Broken links are fixed during archival
   - Clear redirects to current information
   - Documentation stays navigable

4. **Reduced Maintenance Burden**
   - Focus maintenance on active docs
   - Archive doesn't need regular updates
   - Clear criteria reduce decision fatigue

---

## Related Documents

- [Documentation Maintenance Guide](./DOCUMENTATION_MAINTENANCE_GUIDE.md) - Daily maintenance workflows
- [Documentation Health Index](./DOCUMENTATION_HEALTH_INDEX.md) - Quality assessment
- [Fix Broken Links Guide](./FIX_BROKEN_LINKS_GUIDE.md) - Link repair procedures
- [INDEX.md](./INDEX.md#-archive) - Archive navigation

---

**Last Updated:** 2025-10-22
**Next Review:** 2026-01-22 (Quarterly)
